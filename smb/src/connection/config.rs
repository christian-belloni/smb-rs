//! Connection configuration settings.

use std::time::Duration;

use crate::packets::{guid::Guid, smb2::Dialect};

/// Specifies the encryption mode for the connection.
/// Use this as part of the [ConnectionConfig] to specify the encryption mode for the connection.
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
    /// Specifies the timeout for the connection.
    /// If unset, defaults to [`ConnectionConfig::DEFAULT_TIMEOUT`].
    /// 0 means wait forever.
    /// Access the timeout using the [`ConnectionConfig::timeout()`] method.
    pub timeout: Option<Duration>,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub min_dialect: Option<Dialect>,

    /// Specifies the minimum and maximum dialects to be used in the connection.
    ///
    /// Note, that if set, the minimum dialect must be less than or equal to the maximum dialect.
    pub max_dialect: Option<Dialect>,

    /// Sets the encryption mode for the connection.
    /// See [EncryptionMode] for more information.
    pub encryption_mode: EncryptionMode,

    /// Whether to enable compression, if supported by the server and specified connection dialects.
    ///
    /// Note: you must also have compression features enabled when building the crate, otherwise compression
    /// would not be available. *The compression feature is enabled by default.*
    pub compression_enabled: bool,

    /// Specifies the client name to be used in the SMB2 negotiate request.
    pub client_name: Option<String>,

    /// Specifies the GUID of the client to be used in the SMB2 negotiate request.
    /// If not set, a random GUID will be generated.
    pub client_guid: Option<Guid>,

    /// Specifies whether to disable support for Server-to-client notifications.
    /// If set to true, the client will NOT support notifications.
    pub disable_notifications: bool,
}

impl ConnectionConfig {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Validates common configuration settings.
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

    pub fn timeout(&self) -> Duration {
        self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT)
    }
}
