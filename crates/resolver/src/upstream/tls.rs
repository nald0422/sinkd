//! Certificate trust for the encrypted upstreams.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// Which certificate authorities DoH and DoT upstreams are checked against.
#[derive(Debug, Clone, Default)]
pub enum Roots {
    /// The operating system's verifier and trust settings (Security.framework
    /// on macOS). sinkd never adds a root of its own.
    #[default]
    System,
    /// Only these roots, DER-encoded. For tests against local servers.
    Only(Arc<Vec<Vec<u8>>>),
}

/// rustls is built with *ring* only; the HTTP client finds it as the
/// process default. Installing twice is harmless.
pub(super) fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl Roots {
    /// A TLS client config for DoT.
    pub(super) fn client_config(&self) -> Result<ClientConfig, rustls::Error> {
        install_crypto();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()?;
        Ok(match self {
            Roots::System => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    rustls_platform_verifier::Verifier::new(provider)?,
                ))
                .with_no_client_auth(),
            Roots::Only(ders) => {
                let mut store = RootCertStore::empty();
                for der in ders.iter() {
                    store.add(CertificateDer::from(der.clone()))?;
                }
                builder.with_root_certificates(store).with_no_client_auth()
            }
        })
    }

    /// Applies these roots to an HTTP client for DoH.
    pub(super) fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, reqwest::Error> {
        install_crypto();
        Ok(match self {
            Roots::System => builder,
            Roots::Only(ders) => builder.tls_certs_only(
                ders.iter()
                    .map(|der| reqwest::Certificate::from_der(der))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        })
    }
}
