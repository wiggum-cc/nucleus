use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum NucleusError {
    #[error("Failed to create namespace: {0}")]
    NamespaceError(String),

    #[error("Failed to configure cgroup: {0}")]
    CgroupError(String),

    #[error("Failed to mount filesystem: {0}")]
    FilesystemError(String),

    #[error("Failed to pivot root: {0}")]
    PivotRootError(String),

    #[error("Failed to populate context: {0}")]
    ContextError(String),

    #[error("Failed to drop capabilities: {0}")]
    CapabilityError(String),

    #[error("Failed to apply seccomp filter: {0}")]
    SeccompError(String),

    #[error("Invalid resource limit: {0}")]
    InvalidResourceLimit(String),

    #[error("Invalid path: {path:?}")]
    InvalidPath { path: PathBuf },

    #[error("Process execution failed: {0}")]
    ExecError(String),

    #[error("gVisor runtime error: {0}")]
    GVisorError(String),

    #[error("Syscall error: {0}")]
    SyscallError(#[from] nix::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid state transition: from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },
}

pub type Result<T> = std::result::Result<T, NucleusError>;
