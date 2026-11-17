//! Where tunnel configurations come from.
//!
//! The kynvpn backend (sign-in, server list, key registration) is still being
//! designed, so the app goes through this trait and only [`StaticSource`]
//! exists today. The backend client will be another implementation, built
//! on `klbfw`.

use crate::config::TunnelConfig;

/// A place to choose a server from and get a configuration for it.
pub trait ConfigSource: Send + Sync {
    /// The locations the user can pick, in display order.
    fn locations(&self) -> Vec<Location>;

    /// A configuration for one location. For the backend this registers our
    /// public key with the server and returns the address it assigned.
    fn config_for(&self, location_id: &str) -> Result<TunnelConfig, SourceError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub id: String,
    pub name: String,
    /// ISO 3166-1 alpha-2, for the flag.
    pub country: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("unknown location {0}")]
    UnknownLocation(String),
    #[error("{0}")]
    Other(String),
}

/// A single configuration the user imported (a `wg-quick` file).
pub struct StaticSource {
    pub name: String,
    pub config: TunnelConfig,
}

impl ConfigSource for StaticSource {
    fn locations(&self) -> Vec<Location> {
        vec![Location {
            id: "static".into(),
            name: self.name.clone(),
            country: String::new(),
        }]
    }

    fn config_for(&self, location_id: &str) -> Result<TunnelConfig, SourceError> {
        if location_id == "static" {
            Ok(self.config.clone())
        } else {
            Err(SourceError::UnknownLocation(location_id.into()))
        }
    }
}
