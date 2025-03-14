use std::time::Duration;

use crate::packets::smb2::Dialect;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncryptionMode {
    /// Encryption is allowed but not required, it's up to the server to decide.
    #[default]
    Allowed,
    /// Encryption is required, and connection will fail if the server does not support it.
    Required,
    /// Encryption is disabled, server might fail the connection if it requires encryption.
    Disabled,
}

impl EncryptionMode {
    /// Returns true if encryption is required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }

    /// Returns true if encryption is disabled.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Specifies the configuration for a connection.
#[derive(Debug, Default, Clone)]
pub struct ConnectionConfig {
    pub timeout: Option<Duration>,
    pub min_dialect: Option<Dialect>,
    pub max_dialect: Option<Dialect>,
    pub encryption_mode: EncryptionMode,
}

impl ConnectionConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> crate::Result<()> {
        // Make sure dialects min <= max.
        if let (Some(min), Some(max)) = (self.min_dialect, self.max_dialect) {
            if min > max {
                return Err(crate::Error::InvalidConfiguration(
                    "Minimum dialect is greater than maximum dialect".to_string(),
                ));
            }
        }
        Ok(())
    }
}
