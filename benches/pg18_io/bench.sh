#!/usr/bin/env bash
# PostgreSQL 18 Benchmark: default I/O vs io_uring, baremetal vs Nucleus
#
# Usage: sudo pg18-bench [--scale=N] [--clients=N] [--duration=N] [--skip-init]
#
# Requires: root (for Nucleus container operations and kernel tuning)
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCALE="${SCALE:-50}"            # pgbench scale factor (50 ~ 800 MB dataset)
CLIENTS="${CLIENTS:-8}"         # concurrent pgbench clients
DURATION="${DURATION:-60}"      # seconds per pgbench run
RUNS="${RUNS:-3}"               # repeat each benchmark N times
RESULTS_DIR="${RESULTS_DIR:-./results/$(date +%Y%m%d_%H%M%S)}"
SKIP_INIT="${SKIP_INIT:-0}"

for arg in "$@"; do
  case "$arg" in
    --scale=*)    SCALE="${arg#*=}" ;;
    --clients=*)  CLIENTS="${arg#*=}" ;;
    --duration=*) DURATION="${arg#*=}" ;;
    --runs=*)     RUNS="${arg#*=}" ;;
    --skip-init)  SKIP_INIT=1 ;;
    --help|-h)
      echo "Usage: pg18-bench [--scale=N] [--clients=N] [--duration=N] [--runs=N] [--skip-init]"
      exit 0
      ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

mkdir -p "$RESULTS_DIR"

echo "=== PG18 I/O Benchmark ==="
echo "  scale=$SCALE  clients=$CLIENTS  duration=${DURATION}s  runs=$RUNS"
echo "  results -> $RESULTS_DIR"
echo ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PG_PORT_BARE=5480
PG_PORT_NUCLEUS=5481

# PostgreSQL refuses to run as root. Use SUDO_USER to drop privileges for all
# PG operations (initdb, pg_ctl, pgbench, psql). Nucleus commands stay as root.
PG_USER="${SUDO_USER:-nobody}"
PG_UID="$(id -u "$PG_USER")"
PG_GID="$(id -g "$PG_USER")"

as_pg() {
  # Run a command as the unprivileged PG_USER
  sudo -u "$PG_USER" --preserve-env=PATH "$@"
}

cleanup_pg() {
  local pgdata="$1"
  local port="$2"
  if [ -f "$pgdata/postmaster.pid" ]; then
    as_pg pg_ctl -D "$pgdata" -m immediate stop 2>/dev/null || true
    sleep 1
  fi
  fuser -k "${port}/tcp" 2>/dev/null || true
}

init_pgdata() {
  local pgdata="$1"

  rm -rf "$pgdata"
  mkdir -p "$pgdata"
  chown "$PG_USER" "$pgdata"
  as_pg initdb -D "$pgdata" --no-locale --encoding=UTF8 -A trust
}

write_pg_conf() {
  local pgdata="$1"
  local port="$2"
  local io_method="$3"    # "worker" or "io_uring"

  cat > "$pgdata/postgresql.conf" <<PGEOF
# --- Benchmark tuning ---
listen_addresses = '127.0.0.1'
port = $port
unix_socket_directories = '$pgdata'
max_connections = 100

# Memory
shared_buffers = '256MB'
work_mem = '16MB'
maintenance_work_mem = '128MB'
effective_cache_size = '512MB'

# WAL
wal_level = minimal
max_wal_senders = 0
fsync = on
synchronous_commit = on
wal_buffers = '16MB'
checkpoint_completion_target = 0.9
max_wal_size = '1GB'

# I/O method (PG18+)
io_method = '$io_method'

# Logging (minimal for benchmarks)
logging_collector = off
log_min_messages = warning

# Misc
jit = off
PGEOF

  cat > "$pgdata/pg_hba.conf" <<HBAEOF
local   all   all                 trust
host    all   all   127.0.0.1/32  trust
HBAEOF

  chown "$PG_USER" "$pgdata/postgresql.conf" "$pgdata/pg_hba.conf"
}

start_pg() {
  local pgdata="$1"
  local port="$2"

  if ! as_pg pg_ctl -D "$pgdata" -l "$pgdata/server.log" -w -t 10 start; then
    echo "ERROR: pg_ctl start failed" >&2
    echo "--- server.log ---" >&2
    cat "$pgdata/server.log" >&2
    return 1
  fi

  for _ in $(seq 1 30); do
    if as_pg pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
      return 0
    fi
    sleep 0.3
  done
  echo "ERROR: PostgreSQL failed to start (port $port)" >&2
  echo "--- server.log ---" >&2
  cat "$pgdata/server.log" >&2
  return 1
}

stop_pg() {
  local pgdata="$1"
  as_pg pg_ctl -D "$pgdata" -m fast stop 2>/dev/null || true
}

run_pgbench_init() {
  local port="$1"

  as_pg createdb -h 127.0.0.1 -p "$port" pgbench 2>/dev/null || true
  as_pg pgbench -h 127.0.0.1 -p "$port" -i -s "$SCALE" pgbench
}

run_pgbench() {
  local port="$1"
  local mode="$2"      # "tpcb" or "select"
  local outfile="$3"

  local proto_flag=""
  case "$mode" in
    tpcb)   proto_flag="" ;;
    select) proto_flag="-S" ;;
  esac

  echo "  -> pgbench $mode (${DURATION}s, ${CLIENTS} clients) ..."

  as_pg pgbench -h 127.0.0.1 -p "$port" \
    -c "$CLIENTS" -j "$CLIENTS" \
    -T "$DURATION" \
    $proto_flag \
    --progress=10 \
    pgbench 2>&1 | tee "$outfile"
}

extract_tps() {
  grep -oP 'tps = \K[0-9.]+(?= \(without)' "$1" || echo "0"
}

extract_latency() {
  grep -oP 'latency average = \K[0-9.]+' "$1" || echo "0"
}

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (for Nucleus and kernel tuning)" >&2
  exit 1
fi

if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
  echo "ERROR: run via 'sudo pg18-bench', not as a root login" >&2
  echo "       (SUDO_USER is needed to drop privileges for PostgreSQL)" >&2
  exit 1
fi

if ! grep -q io_uring /proc/kallsyms 2>/dev/null; then
  echo "WARNING: io_uring may not be available in this kernel" >&2
fi

echo "--- System info ---"
uname -a
echo "CPUs: $(nproc)"
echo "Memory: $(free -h | awk '/^Mem:/{print $2}')"
echo ""

# ---------------------------------------------------------------------------
# Build test matrix
# ---------------------------------------------------------------------------
declare -a ENVS=("baremetal" "nucleus")
declare -a IO_MODES=("worker" "io_uring")
declare -a WORKLOADS=("tpcb" "select")

TMPBASE="$(mktemp -d /tmp/pg18bench.XXXXXX)"
chown "$PG_USER" "$TMPBASE"
trap 'cleanup_pg "$TMPBASE/pgdata_bare_worker" "$PG_PORT_BARE" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_bare_io_uring" "$PG_PORT_BARE" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_nucleus_worker" "$PG_PORT_NUCLEUS" 2>/dev/null; cleanup_pg "$TMPBASE/pgdata_nucleus_io_uring" "$PG_PORT_NUCLEUS" 2>/dev/null; rm -rf "$TMPBASE"' EXIT

PG_BIN="$(dirname "$(command -v initdb)")"
echo "PG binary dir: $PG_BIN"
echo "PG version: $(postgres --version)"
echo ""

# ---------------------------------------------------------------------------
# Baremetal benchmarks
# ---------------------------------------------------------------------------
run_baremetal_bench() {
  local io_method="$1"
  local pgdata="$TMPBASE/pgdata_bare_${io_method}"
  local port="$PG_PORT_BARE"

  echo ""
  echo "================================================================"
  echo "  BAREMETAL / io_method=$io_method"
  echo "================================================================"

  cleanup_pg "$pgdata" "$port"
  init_pgdata "$pgdata"
  write_pg_conf "$pgdata" "$port" "$io_method"
  start_pg "$pgdata" "$port"

  if [ "$SKIP_INIT" = "0" ]; then
    echo "  Initializing pgbench (scale=$SCALE) ..."
    run_pgbench_init "$port"
  fi

  as_pg psql -h 127.0.0.1 -p "$port" -c "CHECKPOINT;" pgbench

  for workload in "${WORKLOADS[@]}"; do
    for run in $(seq 1 "$RUNS"); do
      local outfile="$RESULTS_DIR/baremetal_${io_method}_${workload}_run${run}.txt"
      echo ""
      echo "  [baremetal/$io_method/$workload run=$run]"
      run_pgbench "$port" "$workload" "$outfile"
    done
  done

  stop_pg "$pgdata"
}

# ---------------------------------------------------------------------------
# Nucleus container benchmarks
# ---------------------------------------------------------------------------
run_nucleus_bench() {
  local io_method="$1"
  local pgdata="$TMPBASE/pgdata_nucleus_${io_method}"
  local port="$PG_PORT_NUCLEUS"

  echo ""
  echo "================================================================"
  echo "  NUCLEUS CONTAINER / io_method=$io_method"
  echo "================================================================"

  cleanup_pg "$pgdata" "$port"

  # Prepare pgdata on host, then run PG inside Nucleus with host networking.
  # The postgres process runs in an isolated namespace (cgroups, namespaces,
  # seccomp) while the data directory is bind-mounted in.
  init_pgdata "$pgdata"
  write_pg_conf "$pgdata" "$port" "$io_method"

  # `nucleus create` runs the container in the foreground, so we background it.
  # - Host network: pgbench on host connects via 127.0.0.1
  # - Bind-mount pgdata + /nix (for PG binaries) + /tmp
  # - trusted + allow-degraded-security: minimize security overhead for apples-to-apples I/O benchmark
  # - native runtime: no gVisor, just namespace/cgroup isolation
  nucleus create \
    --name "pg18-bench-${io_method}" \
    --user "$PG_UID" \
    --group "$PG_GID" \
    --network host \
    --allow-host-network \
    --runtime native \
    --trust-level trusted \
    --allow-degraded-security \
    --allow-chroot-fallback \
    --volume "$pgdata:/pgdata" \
    --volume "/nix:/nix:ro" \
    --volume "/tmp:/tmp" \
    -- "$PG_BIN/postgres" -D /pgdata -p "$port" &

  NUCLEUS_PID=$!

  # Wait for PG to come up inside the container
  for _ in $(seq 1 30); do
    if pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
      break
    fi
    sleep 0.5
  done

  if ! pg_isready -h 127.0.0.1 -p "$port" -q 2>/dev/null; then
    echo "ERROR: PostgreSQL inside Nucleus failed to start (io_method=$io_method)" >&2
    cat "$pgdata/server.log" 2>/dev/null >&2 || true
    kill "$NUCLEUS_PID" 2>/dev/null || true
    return 1
  fi

  if [ "$SKIP_INIT" = "0" ]; then
    echo "  Initializing pgbench (scale=$SCALE) ..."
    run_pgbench_init "$port"
  fi

  as_pg psql -h 127.0.0.1 -p "$port" -c "CHECKPOINT;" pgbench

  for workload in "${WORKLOADS[@]}"; do
    for run in $(seq 1 "$RUNS"); do
      local outfile="$RESULTS_DIR/nucleus_${io_method}_${workload}_run${run}.txt"
      echo ""
      echo "  [nucleus/$io_method/$workload run=$run]"
      run_pgbench "$port" "$workload" "$outfile"
    done
  done

  # Graceful shutdown: tell PG to stop, then reap the nucleus process
  as_pg psql -h 127.0.0.1 -p "$port" -c \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" \
    pgbench 2>/dev/null || true
  as_pg pg_ctl -D "$pgdata" -m fast stop 2>/dev/null || true
  kill "$NUCLEUS_PID" 2>/dev/null || true
  wait "$NUCLEUS_PID" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Run all benchmarks
# ---------------------------------------------------------------------------
for io_mode in "${IO_MODES[@]}"; do
  run_nucleus_bench "$io_mode"
done

for io_mode in "${IO_MODES[@]}"; do
  run_baremetal_bench "$io_mode"
done

# ---------------------------------------------------------------------------
# Aggregate & compare results
# ---------------------------------------------------------------------------
echo ""
echo ""
echo "================================================================"
echo "  RESULTS SUMMARY"
echo "================================================================"
echo ""

SUMMARY_FILE="$RESULTS_DIR/summary.csv"
echo "env,io_method,workload,run,tps,latency_ms" > "$SUMMARY_FILE"

for env in "${ENVS[@]}"; do
  for io_mode in "${IO_MODES[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
      for run in $(seq 1 "$RUNS"); do
        f="$RESULTS_DIR/${env}_${io_mode}_${workload}_run${run}.txt"
        if [ -f "$f" ]; then
          tps="$(extract_tps "$f")"
          lat="$(extract_latency "$f")"
          echo "$env,$io_mode,$workload,$run,$tps,$lat" >> "$SUMMARY_FILE"
        fi
      done
    done
  done
done

echo "Raw CSV: $SUMMARY_FILE"
echo ""

# Print comparison table
printf "%-12s %-10s %-8s %10s %10s %10s %12s\n" \
  "ENV" "IO_MODE" "WORKLOAD" "AVG_TPS" "MIN_TPS" "MAX_TPS" "AVG_LAT(ms)"
printf '%.0s-' {1..76}
echo ""

for env in "${ENVS[@]}"; do
  for io_mode in "${IO_MODES[@]}"; do
    for workload in "${WORKLOADS[@]}"; do
      stats=$(awk -F, -v e="$env" -v m="$io_mode" -v w="$workload" '
        $1==e && $2==m && $3==w {
          n++; sum_tps+=$5; sum_lat+=$6
          if(n==1 || $5<min_tps) min_tps=$5
          if(n==1 || $5>max_tps) max_tps=$5
        }
        END {
          if(n>0) printf "%.1f %.1f %.1f %.3f", sum_tps/n, min_tps, max_tps, sum_lat/n
          else printf "- - - -"
        }' "$SUMMARY_FILE")

      read -r avg_tps min_tps max_tps avg_lat <<< "$stats"
      printf "%-12s %-10s %-8s %10s %10s %10s %12s\n" \
        "$env" "$io_mode" "$workload" "$avg_tps" "$min_tps" "$max_tps" "$avg_lat"
    done
  done
done

echo ""
echo "--- Relative performance (vs baremetal/worker baseline) ---"
echo ""

for workload in "${WORKLOADS[@]}"; do
  baseline_tps=$(awk -F, -v w="$workload" '
    $1=="baremetal" && $2=="worker" && $3==w { n++; s+=$5 }
    END { if(n>0) printf "%.1f", s/n; else print "1" }' "$SUMMARY_FILE")

  printf "%-8s baseline (baremetal/worker): %s TPS\n" "$workload" "$baseline_tps"

  for env in "${ENVS[@]}"; do
    for io_mode in "${IO_MODES[@]}"; do
      if [ "$env" = "baremetal" ] && [ "$io_mode" = "worker" ]; then
        continue
      fi
      avg_tps=$(awk -F, -v e="$env" -v m="$io_mode" -v w="$workload" '
        $1==e && $2==m && $3==w { n++; s+=$5 }
        END { if(n>0) printf "%.1f", s/n; else print "0" }' "$SUMMARY_FILE")

      if [ "$baseline_tps" != "0" ] && [ "$baseline_tps" != "1" ]; then
        pct=$(awk "BEGIN { printf \"%.1f\", ($avg_tps / $baseline_tps) * 100 }")
        delta=$(awk "BEGIN { printf \"%+.1f\", (($avg_tps / $baseline_tps) - 1) * 100 }")
        printf "  %-12s %-10s -> %10s TPS  (%s%% of baseline, %s%%)\n" \
          "$env" "$io_mode" "$avg_tps" "$pct" "$delta"
      fi
    done
  done
  echo ""
done

echo ""
echo "--- Nucleus overhead (same I/O mode) ---"
echo ""

for io_mode in "${IO_MODES[@]}"; do
  for workload in "${WORKLOADS[@]}"; do
    bare_tps=$(awk -F, -v m="$io_mode" -v w="$workload" '
      $1=="baremetal" && $2==m && $3==w { n++; s+=$5 }
      END { if(n>0) printf "%.1f", s/n; else print "0" }' "$SUMMARY_FILE")

    nuc_tps=$(awk -F, -v m="$io_mode" -v w="$workload" '
      $1=="nucleus" && $2==m && $3==w { n++; s+=$5 }
      END { if(n>0) printf "%.1f", s/n; else print "0" }' "$SUMMARY_FILE")

    if [ "$bare_tps" != "0" ]; then
      overhead=$(awk "BEGIN { printf \"%.2f\", (1 - ($nuc_tps / $bare_tps)) * 100 }")
      printf "  %-10s %-8s: baremetal=%s  nucleus=%s  overhead=%s%%\n" \
        "$io_mode" "$workload" "$bare_tps" "$nuc_tps" "$overhead"
    fi
  done
done

echo ""
echo "Full results in: $RESULTS_DIR"
echo "Done."
