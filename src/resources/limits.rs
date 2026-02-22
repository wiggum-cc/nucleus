use crate::error::{NucleusError, Result};

/// Resource limits configuration
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Memory limit in bytes (None = unlimited)
    pub memory_bytes: Option<u64>,
    /// CPU quota in microseconds per period
    pub cpu_quota_us: Option<u64>,
    /// CPU period in microseconds (default: 100000 = 100ms)
    pub cpu_period_us: u64,
    /// Maximum number of PIDs (None = unlimited)
    pub pids_max: Option<u64>,
}

impl ResourceLimits {
    /// Create unlimited resource limits
    pub fn unlimited() -> Self {
        Self {
            memory_bytes: None,
            cpu_quota_us: None,
            cpu_period_us: 100_000, // 100ms default period
            pids_max: None,
        }
    }

    /// Parse memory limit from string (e.g., "512M", "1G")
    pub fn parse_memory(s: &str) -> Result<u64> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NucleusError::InvalidResourceLimit(
                "Empty memory limit".to_string(),
            ));
        }

        let (num_str, multiplier) = if s.ends_with('K') || s.ends_with('k') {
            (&s[..s.len() - 1], 1024u64)
        } else if s.ends_with('M') || s.ends_with('m') {
            (&s[..s.len() - 1], 1024 * 1024)
        } else if s.ends_with('G') || s.ends_with('g') {
            (&s[..s.len() - 1], 1024 * 1024 * 1024)
        } else if s.ends_with('T') || s.ends_with('t') {
            (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024)
        } else {
            // No suffix, assume bytes
            (s, 1)
        };

        let num: u64 = num_str.parse().map_err(|_| {
            NucleusError::InvalidResourceLimit(format!("Invalid memory value: {}", s))
        })?;

        Ok(num * multiplier)
    }

    /// Set memory limit from string (e.g., "512M", "1G")
    pub fn with_memory(mut self, limit: &str) -> Result<Self> {
        self.memory_bytes = Some(Self::parse_memory(limit)?);
        Ok(self)
    }

    /// Set CPU limit in cores (e.g., 2.5 cores)
    pub fn with_cpu_cores(mut self, cores: f64) -> Result<Self> {
        if cores <= 0.0 {
            return Err(NucleusError::InvalidResourceLimit(
                "CPU cores must be positive".to_string(),
            ));
        }
        // Convert cores to quota: cores * period
        let quota = (cores * self.cpu_period_us as f64) as u64;
        self.cpu_quota_us = Some(quota);
        Ok(self)
    }

    /// Set maximum number of PIDs
    pub fn with_pids(mut self, max_pids: u64) -> Result<Self> {
        if max_pids == 0 {
            return Err(NucleusError::InvalidResourceLimit(
                "Max PIDs must be positive".to_string(),
            ));
        }
        self.pids_max = Some(max_pids);
        Ok(self)
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory() {
        assert_eq!(ResourceLimits::parse_memory("1024").unwrap(), 1024);
        assert_eq!(ResourceLimits::parse_memory("512K").unwrap(), 512 * 1024);
        assert_eq!(ResourceLimits::parse_memory("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(
            ResourceLimits::parse_memory("2G").unwrap(),
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn test_parse_memory_invalid() {
        assert!(ResourceLimits::parse_memory("").is_err());
        assert!(ResourceLimits::parse_memory("abc").is_err());
        assert!(ResourceLimits::parse_memory("M").is_err());
    }

    #[test]
    fn test_with_cpu_cores() {
        let limits = ResourceLimits::unlimited();
        let limits = limits.with_cpu_cores(2.0).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(200_000)); // 2.0 * 100_000
    }

    #[test]
    fn test_with_cpu_cores_fractional() {
        let limits = ResourceLimits::unlimited();
        let limits = limits.with_cpu_cores(0.5).unwrap();
        assert_eq!(limits.cpu_quota_us, Some(50_000)); // 0.5 * 100_000
    }

    #[test]
    fn test_with_cpu_cores_invalid() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.with_cpu_cores(0.0).is_err());
        assert!(ResourceLimits::unlimited().with_cpu_cores(-1.0).is_err());
    }
}
