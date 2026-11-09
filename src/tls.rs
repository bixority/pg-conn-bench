//! TLS client configuration for `--sslmode require`.
//!
//! Like libpq's `sslmode=require`, the connection is encrypted but the server certificate is not
//! verified. Benchmarked clusters often use self-signed certificates, so verification would fail.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

#[derive(Debug)]
struct NoVerify {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Build a client config that encrypts without verifying the server certificate.
pub fn no_verify_config() -> Result<ClientConfig, Error> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let algorithms = provider.signature_verification_algorithms;

    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify { algorithms }))
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_verify_config_builds() {
        assert!(no_verify_config().is_ok());
    }

    #[test]
    fn verifier_accepts_any_certificate() {
        let verifier = NoVerify {
            algorithms: aws_lc_rs::default_provider().signature_verification_algorithms,
        };
        let garbage = CertificateDer::from(vec![0u8, 1, 2, 3]);
        let name = ServerName::try_from("example.invalid").unwrap();

        let result = verifier.verify_server_cert(&garbage, &[], &name, &[], UnixTime::now());

        assert!(result.is_ok());
    }

    #[test]
    fn verifier_offers_schemes() {
        let verifier = NoVerify {
            algorithms: aws_lc_rs::default_provider().signature_verification_algorithms,
        };
        assert!(!verifier.supported_verify_schemes().is_empty());
    }
}
