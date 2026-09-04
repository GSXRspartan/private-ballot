//! Bounded transport-error mapping (Section F).
//!
//! [`TransportError`] is the single, bounded error type returned by the
//! transport traits. Every variant is a fixed, self-describing category — no
//! variant carries unbounded third-party error text, endpoint credentials,
//! account references, key handles, or wallet identifiers. Diagnostics are
//! fixed strings or already-bounded project-owned errors.

use core::fmt;

/// Bounded transport-error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportErrorCategory {
    /// The service could not be reached at all (connection refused, DNS
    /// failure, host unavailable).
    ConnectionRefused,
    /// The request or response timed out; the observable state is now unknown.
    Timeout,
    /// A TLS failure occurred while establishing the connection.
    TlsFailure,
    /// Authentication failed (401, invalid credentials, expired token).
    AuthenticationFailure,
    /// The service returned an HTTP status error other than 401/404.
    HttpStatusError,
    /// The response body could not be parsed into the expected shape.
    MalformedResponse,
    /// The service reported a schema or API version this adapter does not
    /// support.
    UnsupportedApi,
    /// The requested resource (walletd request or indexer receipt) was not
    /// found.
    NotFound,
    /// The service is temporarily unavailable (503 or equivalent).
    ServiceUnavailable,
    /// The executor could not block on the async call.
    ExecutorUnavailable,
    /// Walletd rejected execution because the paid fee was below the required
    /// fee. The bounded numeric details are carried separately.
    InsufficientFeesPaid,
    /// A bounded, uncategorized transport failure.
    Unknown,
}

impl TransportErrorCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "TRANSPORT_CONNECTION_REFUSED",
            Self::Timeout => "TRANSPORT_TIMEOUT",
            Self::TlsFailure => "TRANSPORT_TLS_FAILURE",
            Self::AuthenticationFailure => "TRANSPORT_AUTHENTICATION_FAILURE",
            Self::HttpStatusError => "TRANSPORT_HTTP_STATUS_ERROR",
            Self::MalformedResponse => "TRANSPORT_MALFORMED_RESPONSE",
            Self::UnsupportedApi => "TRANSPORT_UNSUPPORTED_API",
            Self::NotFound => "TRANSPORT_NOT_FOUND",
            Self::ServiceUnavailable => "TRANSPORT_SERVICE_UNAVAILABLE",
            Self::ExecutorUnavailable => "TRANSPORT_EXECUTOR_UNAVAILABLE",
            Self::InsufficientFeesPaid => "TRANSPORT_INSUFFICIENT_FEES_PAID",
            Self::Unknown => "TRANSPORT_UNKNOWN",
        }
    }
}

impl fmt::Display for TransportErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bounded transport error returned by the wire-transport traits.
///
/// No variant carries unbounded third-party text, secrets, or identifiers. The
/// `category` field is the stable machine-readable code; `http_status` is
/// present only for HTTP status errors and is a bounded `u16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    category: TransportErrorCategory,
    http_status: Option<u16>,
    paid_fee: Option<u64>,
    required_fee: Option<u64>,
}

impl TransportError {
    /// Creates a transport error from a category, with no HTTP status.
    #[must_use]
    pub const fn from_category(category: TransportErrorCategory) -> Self {
        Self {
            category,
            http_status: None,
            paid_fee: None,
            required_fee: None,
        }
    }

    /// Creates a transport error with a bounded HTTP status code.
    #[must_use]
    pub const fn with_status(category: TransportErrorCategory, http_status: u16) -> Self {
        Self {
            category,
            http_status: Some(http_status),
            paid_fee: None,
            required_fee: None,
        }
    }

    /// Creates a bounded insufficient-fees error.
    #[must_use]
    pub const fn insufficient_fees_paid(paid_fee: u64, required_fee: u64) -> Self {
        Self {
            category: TransportErrorCategory::InsufficientFeesPaid,
            http_status: None,
            paid_fee: Some(paid_fee),
            required_fee: Some(required_fee),
        }
    }

    /// Returns the stable machine-readable error category.
    #[must_use]
    pub const fn category(&self) -> TransportErrorCategory {
        self.category
    }

    /// Returns the bounded HTTP status code, if one was recorded.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        self.http_status
    }

    /// Returns `(paid, required)` for an insufficient-fees rejection.
    #[must_use]
    pub const fn insufficient_fee_details(&self) -> Option<(u64, u64)> {
        match (self.paid_fee, self.required_fee) {
            (Some(paid), Some(required)) => Some((paid, required)),
            _ => None,
        }
    }

    /// Returns the stable machine-readable code string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.category.as_str()
    }

    /// Returns `true` if this error represents a not-found response.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self.category, TransportErrorCategory::NotFound)
    }

    /// Maps a pinned [`WalletDaemonClientError`] into a bounded
    /// [`TransportError`].
    ///
    /// No third-party error text, credential, or identifier is preserved. The
    /// mapping is total and deterministic.
    #[must_use]
    pub fn from_walletd_client(
        error: &tari_ootle_walletd_client::error::WalletDaemonClientError,
    ) -> Self {
        use tari_ootle_walletd_client::error::WalletDaemonClientError;
        match error {
            WalletDaemonClientError::RequestFailed { source } => {
                if source.is_timeout() {
                    Self::from_category(TransportErrorCategory::Timeout)
                } else if source.is_connect() {
                    Self::from_category(TransportErrorCategory::ConnectionRefused)
                } else {
                    Self::from_category(TransportErrorCategory::Unknown)
                }
            }
            WalletDaemonClientError::Unauthorized { .. } => {
                Self::from_category(TransportErrorCategory::AuthenticationFailure)
            }
            WalletDaemonClientError::RequestFailedWithStatus { code, message } => {
                if let Some((paid, required)) = parse_insufficient_fees_paid(message) {
                    return Self::insufficient_fees_paid(paid, required);
                }
                let status = u16::try_from(*code).unwrap_or(0);
                match status {
                    401 => Self::from_category(TransportErrorCategory::AuthenticationFailure),
                    404 => Self::from_category(TransportErrorCategory::NotFound),
                    503 => Self::from_category(TransportErrorCategory::ServiceUnavailable),
                    _ => Self::with_status(TransportErrorCategory::HttpStatusError, status),
                }
            }
            WalletDaemonClientError::InvalidResponse { message } => {
                if let Some((paid, required)) = parse_insufficient_fees_paid(message) {
                    return Self::insufficient_fees_paid(paid, required);
                }
                Self::from_category(TransportErrorCategory::MalformedResponse)
            }
            WalletDaemonClientError::DeserializeResponse { .. } => {
                Self::from_category(TransportErrorCategory::MalformedResponse)
            }
            WalletDaemonClientError::SerializeRequest { .. } => {
                Self::from_category(TransportErrorCategory::UnsupportedApi)
            }
        }
    }

    /// Maps a pinned [`IndexerRestClientError`] into a bounded
    /// [`TransportError`].
    ///
    /// No third-party error text, credential, or identifier is preserved. The
    /// mapping is total and deterministic.
    #[must_use]
    pub fn from_indexer_client(error: &tari_indexer_client::error::IndexerRestClientError) -> Self {
        use tari_indexer_client::error::IndexerRestClientError;
        match error {
            IndexerRestClientError::RequestFailed { source } => {
                if source.is_timeout() {
                    Self::from_category(TransportErrorCategory::Timeout)
                } else if source.is_connect() {
                    Self::from_category(TransportErrorCategory::ConnectionRefused)
                } else {
                    Self::from_category(TransportErrorCategory::Unknown)
                }
            }
            IndexerRestClientError::ErrorResponse { source, .. } => {
                let status = source.status().map(|s| s.as_u16()).unwrap_or(0);
                match status {
                    401 => Self::from_category(TransportErrorCategory::AuthenticationFailure),
                    404 => Self::from_category(TransportErrorCategory::NotFound),
                    503 => Self::from_category(TransportErrorCategory::ServiceUnavailable),
                    _ => Self::with_status(TransportErrorCategory::HttpStatusError, status),
                }
            }
            IndexerRestClientError::RequestFailedWithStatus { code, .. } => {
                let status = u16::try_from(*code).unwrap_or(0);
                match status {
                    401 => Self::from_category(TransportErrorCategory::AuthenticationFailure),
                    404 => Self::from_category(TransportErrorCategory::NotFound),
                    503 => Self::from_category(TransportErrorCategory::ServiceUnavailable),
                    _ => Self::with_status(TransportErrorCategory::HttpStatusError, status),
                }
            }
            IndexerRestClientError::DeserializeResponse { .. } => {
                Self::from_category(TransportErrorCategory::MalformedResponse)
            }
            IndexerRestClientError::SerializeRequest { .. } => {
                Self::from_category(TransportErrorCategory::UnsupportedApi)
            }
            IndexerRestClientError::InvalidResponse { .. } => {
                Self::from_category(TransportErrorCategory::MalformedResponse)
            }
            IndexerRestClientError::RequestInvariant { .. } => {
                Self::from_category(TransportErrorCategory::UnsupportedApi)
            }
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.http_status {
            _ if self.category == TransportErrorCategory::InsufficientFeesPaid => {
                match self.insufficient_fee_details() {
                    Some((paid, required)) => write!(
                        f,
                        "{}: paid={} required={}",
                        self.category.as_str(),
                        paid,
                        required
                    ),
                    None => f.write_str(self.category.as_str()),
                }
            }
            Some(status) => write!(f, "{}: HTTP {}", self.category.as_str(), status),
            None => f.write_str(self.category.as_str()),
        }
    }
}

impl std::error::Error for TransportError {}

fn parse_insufficient_fees_paid(message: &str) -> Option<(u64, u64)> {
    if !message.contains("InsufficientFeesPaid") && !message.contains("Insufficient fees paid") {
        return None;
    }
    let mut numbers = message
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok());
    let paid = numbers.next()?;
    let required = numbers.next()?;
    Some((paid, required))
}
