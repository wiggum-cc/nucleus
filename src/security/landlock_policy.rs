//! Landlock policy: external TOML-based filesystem access rules.
//!
//! Allows operators to define per-service Landlock rules in a standalone
//! TOML file, replacing the hardcoded default policy.
//!
//! # Example
//!
//! ```toml
//! min_abi = 3
//!
//! [[rules]]
//! path = "/bin"
//! access = ["read", "execute"]
//!
//! [[rules]]
//! path = "/tmp"
//! access = ["read", "write", "create", "remove"]
//!
//! [[rules]]
//! path = "/run/secrets"
//! access = ["read"]
//! ```

use crate::error::{NucleusError, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use serde::Deserialize;
use tracing::{info, warn};

/// Target ABI for access flag construction.
const TARGET_ABI: ABI = ABI::V5;

/// Parsed Landlock policy from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct LandlockPolicy {
    /// Minimum required ABI version (1-5). Default: 3.
    #[serde(default = "default_min_abi")]
    pub min_abi: u8,

    /// Filesystem access rules.
    #[serde(default)]
    pub rules: Vec<LandlockRule>,
}

fn default_min_abi() -> u8 {
    3
}

/// A single filesystem access rule.
#[derive(Debug, Clone, Deserialize)]
pub struct LandlockRule {
    /// Path to grant access to.
    pub path: String,

    /// Access permissions: "read", "write", "execute", "create", "remove", "readdir".
    pub access: Vec<String>,
}

impl LandlockPolicy {
    /// Apply this policy, replacing the default hardcoded Landlock rules.
    ///
    /// Returns true if the policy was enforced (fully or partially),
    /// false if not enforced (kernel too old).
    pub fn apply(&self, best_effort: bool) -> Result<bool> {
        let access_all = AccessFs::from_all(TARGET_ABI);

        // Check minimum ABI
        let min_abi_enum = abi_from_version(self.min_abi)?;
        match Ruleset::default().handle_access(AccessFs::from_all(min_abi_enum)) {
            Ok(_) => {
                info!("Landlock ABI >= V{} confirmed", self.min_abi);
            }
            Err(e) => {
                let msg = format!(
                    "Kernel Landlock ABI below required V{}: {}",
                    self.min_abi, e
                );
                if best_effort {
                    warn!("{}", msg);
                    return Ok(false);
                } else {
                    return Err(NucleusError::LandlockError(msg));
                }
            }
        }

        let mut ruleset = Ruleset::default()
            .handle_access(access_all)
            .map_err(ll_err)?
            .create()
            .map_err(ll_err)?;

        for rule in &self.rules {
            let flags = parse_access_flags(&rule.access)?;
            match PathFd::new(&rule.path) {
                Ok(fd) => {
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(fd, flags))
                        .map_err(ll_err)?;
                    info!("Landlock rule: {} => {:?}", rule.path, rule.access);
                }
                Err(e) => {
                    if best_effort {
                        warn!(
                            "Skipping Landlock rule for {:?} (path not accessible: {})",
                            rule.path, e
                        );
                    } else {
                        return Err(NucleusError::LandlockError(format!(
                            "Cannot open path {:?} for Landlock rule: {}",
                            rule.path, e
                        )));
                    }
                }
            }
        }

        let status = ruleset.restrict_self().map_err(ll_err)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                info!(
                    "Landlock custom policy fully enforced ({} rules)",
                    self.rules.len()
                );
                Ok(true)
            }
            RulesetStatus::PartiallyEnforced => {
                info!("Landlock custom policy partially enforced");
                Ok(true)
            }
            RulesetStatus::NotEnforced => {
                warn!("Landlock custom policy not enforced (kernel unsupported)");
                Ok(false)
            }
        }
    }
}

/// Parse access flag strings into AccessFs bitflags.
fn parse_access_flags(names: &[String]) -> Result<landlock::BitFlags<AccessFs>> {
    let mut flags: landlock::BitFlags<AccessFs> = landlock::BitFlags::empty();
    for name in names {
        let flag: landlock::BitFlags<AccessFs> = match name.as_str() {
            "read" => AccessFs::from_read(TARGET_ABI),
            "write" => AccessFs::WriteFile | AccessFs::Truncate,
            "execute" => AccessFs::Execute.into(),
            "create" => {
                AccessFs::MakeChar
                    | AccessFs::MakeDir
                    | AccessFs::MakeReg
                    | AccessFs::MakeSock
                    | AccessFs::MakeFifo
                    | AccessFs::MakeSym
                    | AccessFs::MakeBlock
            }
            "remove" => AccessFs::RemoveDir | AccessFs::RemoveFile,
            "readdir" => AccessFs::ReadDir.into(),
            "all" => AccessFs::from_all(TARGET_ABI),
            _ => {
                return Err(NucleusError::ConfigError(format!(
                    "Unknown Landlock access flag: '{}'. Valid: read, write, execute, create, remove, readdir, all",
                    name
                )));
            }
        };
        flags |= flag;
    }
    Ok(flags)
}

/// Convert a numeric ABI version (1-5) to the landlock crate enum.
fn abi_from_version(version: u8) -> Result<ABI> {
    match version {
        1 => Ok(ABI::V1),
        2 => Ok(ABI::V2),
        3 => Ok(ABI::V3),
        4 => Ok(ABI::V4),
        5 => Ok(ABI::V5),
        _ => Err(NucleusError::ConfigError(format!(
            "Invalid Landlock ABI version: {}. Valid: 1-5",
            version
        ))),
    }
}

fn ll_err(e: landlock::RulesetError) -> NucleusError {
    NucleusError::LandlockError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_policy() {
        let toml = r#"
[[rules]]
path = "/tmp"
access = ["read", "write"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 3);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].path, "/tmp");
    }

    #[test]
    fn test_parse_full_policy() {
        let toml = r#"
min_abi = 5

[[rules]]
path = "/bin"
access = ["read", "execute"]

[[rules]]
path = "/etc"
access = ["read"]

[[rules]]
path = "/tmp"
access = ["read", "write", "create", "remove"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 5);
        assert_eq!(policy.rules.len(), 3);
    }

    #[test]
    fn test_parse_access_flags_valid() {
        let flags = parse_access_flags(&["read".into(), "execute".into()]);
        assert!(flags.is_ok());
    }

    #[test]
    fn test_parse_access_flags_invalid() {
        let flags = parse_access_flags(&["destroy".into()]);
        assert!(flags.is_err());
    }

    #[test]
    fn test_abi_from_version() {
        assert!(matches!(abi_from_version(1), Ok(ABI::V1)));
        assert!(matches!(abi_from_version(5), Ok(ABI::V5)));
        assert!(abi_from_version(0).is_err());
        assert!(abi_from_version(6).is_err());
    }

    #[test]
    fn test_default_min_abi() {
        let toml = r#"
[[rules]]
path = "/"
access = ["readdir"]
"#;
        let policy: LandlockPolicy = toml::from_str(toml).unwrap();
        assert_eq!(policy.min_abi, 3);
    }
}
