use serde::Serialize;
use thiserror::Error;

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 1;
pub const EXIT_INTERFACE: i32 = 2;
pub const EXIT_DEVICE: i32 = 3;
pub const EXIT_MISMATCH: i32 = 4;
pub const EXIT_FORMAT: i32 = 5;
pub const EXIT_WRITE_LOCKED: i32 = 6;
pub const EXIT_PROTOCOL: i32 = 7;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Usage error: {0}")]
    Usage(String),

    #[error("Interface error: {0}")]
    Interface(String),

    #[error("Device/bus error: {0}")]
    Device(String),

    #[error("Verification/field mismatch: {0}")]
    Mismatch(String),

    #[error("Invalid data/image/frame format: {0}")]
    Format(String),

    #[error("WRITE LOCKED: {0}")]
    WriteLocked(String),

    #[error("EtherCAT protocol error: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SSC validation error: {0}")]
    Validation(String),

    #[error("SSC invalid OD/application data: {0}")]
    SscInvalidData(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Interface(_) => EXIT_INTERFACE,
            CliError::Device(_) => EXIT_DEVICE,
            CliError::Mismatch(_) => EXIT_MISMATCH,
            CliError::Format(_) | CliError::Validation(_) | CliError::SscInvalidData(_) => {
                EXIT_FORMAT
            }
            CliError::WriteLocked(_) => EXIT_WRITE_LOCKED,
            CliError::Protocol(_) => EXIT_PROTOCOL,
            CliError::Io(_) => EXIT_USAGE,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            CliError::Usage(_) => "usage_error",
            CliError::Interface(_) => "interface_error",
            CliError::Device(_) => "device_error",
            CliError::Mismatch(_) => "mismatch_error",
            CliError::Format(_) => "format_error",
            CliError::WriteLocked(_) => "write_locked",
            CliError::Protocol(_) => "protocol_error",
            CliError::Io(_) => "io_error",
            CliError::Validation(_) => "validation_error",
            CliError::SscInvalidData(_) => "ssc_invalid_data",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub exit_code: i32,
    pub error_kind: &'static str,
    pub message: String,
}

impl From<&CliError> for ErrorEnvelope {
    fn from(err: &CliError) -> Self {
        Self {
            ok: false,
            exit_code: err.exit_code(),
            error_kind: err.kind_name(),
            message: err.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
