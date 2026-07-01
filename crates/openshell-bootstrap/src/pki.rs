// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use rcgen::{BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, SanType};
use std::net::IpAddr;

/// All PEM-encoded materials produced by [`generate_pki`].
#[allow(clippy::struct_field_names)]
pub struct PkiBundle {
    pub ca_cert_pem: String,
    #[allow(dead_code)]
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Default SANs always included on the server certificate.
const DEFAULT_SERVER_SANS: &[&str] = &[
    "openshell",
    "openshell.openshell.svc",
    "openshell.openshell.svc.cluster.local",
    "localhost",
    "host.docker.internal",
    "127.0.0.1",
];

/// Generate a complete PKI bundle: CA, server cert, and client cert.
///
/// `extra_sans` are additional Subject Alternative Names to add to the server
/// certificate (e.g. the remote host's IP or hostname for remote deployments).
///
/// Certificate validity uses the `rcgen` defaults (1975–4096), which effectively
/// never expire. This is appropriate for an internal dev-cluster PKI where certs
/// are ephemeral to the cluster's lifetime.
pub fn generate_pki(extra_sans: &[String]) -> Result<PkiBundle> {
    // --- CA ---
    let ca_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create CA params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "openshell");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-ca");

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .into_diagnostic()
        .wrap_err("failed to self-sign CA certificate")?;

    // --- Server cert ---
    let server_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate server key")?;
    let server_sans = build_server_sans(extra_sans);
    let mut server_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create server cert params")?;
    server_params.subject_alt_names = server_sans;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-server");

    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .into_diagnostic()
        .wrap_err("failed to sign server certificate")?;

    // --- Client cert (shared by CLI and sandbox pods) ---
    let client_key = KeyPair::generate()
        .into_diagnostic()
        .wrap_err("failed to generate client key")?;
    let mut client_params = CertificateParams::new(Vec::<String>::new())
        .into_diagnostic()
        .wrap_err("failed to create client cert params")?;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "openshell-client");

    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .into_diagnostic()
        .wrap_err("failed to sign client certificate")?;

    Ok(PkiBundle {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    })
}

/// Build the SAN list for the server certificate from defaults + extras.
fn build_server_sans(extra_sans: &[String]) -> Vec<SanType> {
    let mut sans = Vec::new();

    for s in DEFAULT_SERVER_SANS {
        add_san(&mut sans, s);
    }
    for s in extra_sans {
        add_san(&mut sans, s);
    }

    sans
}

/// Add a SAN, automatically choosing `IpAddress` or `DnsName` based on the value.
fn add_san(sans: &mut Vec<SanType>, value: &str) {
    if let Ok(ip) = value.parse::<IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    } else if let Ok(dns) = Ia5String::try_from(value) {
        sans.push(SanType::DnsName(dns));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
    use std::time::Duration;
    use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

    /// Signature algorithms `generate_pki` may use. `KeyPair::generate()` emits
    /// ECDSA P-256/SHA-256 today; include the others so the suite stays valid if
    /// the default ever changes.
    const SIG_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ED25519,
    ];

    /// Decode a single PEM certificate into owned DER bytes.
    fn cert_der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes())
            .expect("PEM did not contain a certificate")
            .into_owned()
    }

    /// Verify that `leaf_pem` chains to the CA in `ca_pem` at the given time,
    /// returning the underlying webpki result so callers can assert success or
    /// inspect the rejection reason.
    fn verify_chain(
        leaf_pem: &str,
        ca_pem: &str,
        time: UnixTime,
        usage: KeyUsage,
    ) -> Result<(), webpki::Error> {
        let ca = cert_der(ca_pem);
        let anchor = anchor_from_trusted_cert(&ca).expect("CA is not a usable trust anchor");
        let leaf = cert_der(leaf_pem);
        let ee = EndEntityCert::try_from(&leaf).expect("leaf is not a valid certificate");
        ee.verify_for_usage(SIG_ALGS, &[anchor], &[], time, usage, None, None)
            .map(|_| ())
    }

    #[test]
    fn generate_pki_produces_valid_pem() {
        let bundle = generate_pki(&["10.0.0.1".to_string(), "myhost.example.com".to_string()])
            .expect("generate_pki failed");

        // All PEM strings should be non-empty and contain PEM markers
        assert!(bundle.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.ca_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(bundle.server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.server_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(bundle.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.client_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_pki_no_extra_sans() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        assert!(bundle.server_cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn build_server_sans_includes_defaults_and_extras() {
        let extras = vec!["192.168.1.100".to_string(), "remote.host".to_string()];
        let sans = build_server_sans(&extras);

        // Should have all default SANs + 2 extras
        assert_eq!(sans.len(), DEFAULT_SERVER_SANS.len() + 2);
    }

    #[test]
    fn build_server_sans_classifies_ip_and_dns() {
        let sans = build_server_sans(&["203.0.113.7".to_string(), "remote.example".to_string()]);

        // "127.0.0.1" (default) and the extra IP must be IpAddress SANs.
        let ip_count = sans
            .iter()
            .filter(|s| matches!(s, SanType::IpAddress(_)))
            .count();
        let dns_count = sans
            .iter()
            .filter(|s| matches!(s, SanType::DnsName(_)))
            .count();
        assert_eq!(
            ip_count, 2,
            "expected the default 127.0.0.1 plus the extra IP"
        );
        assert_eq!(
            dns_count,
            sans.len() - 2,
            "remaining SANs should be DNS names"
        );
    }

    #[test]
    fn add_san_skips_unencodable_values() {
        // A non-ASCII hostname is neither a valid IP nor a valid Ia5String, so it
        // is silently dropped rather than panicking.
        let mut sans = Vec::new();
        add_san(&mut sans, "héllo.example");
        assert!(sans.is_empty());
    }

    #[test]
    fn server_cert_chains_to_issuing_ca() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        verify_chain(
            &bundle.server_cert_pem,
            &bundle.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::server_auth(),
        )
        .expect("server certificate should chain to its issuing CA");
    }

    #[test]
    fn client_cert_chains_to_issuing_ca() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        verify_chain(
            &bundle.client_cert_pem,
            &bundle.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::client_auth(),
        )
        .expect("client certificate should chain to its issuing CA");
    }

    #[test]
    fn cert_signed_by_wrong_ca_is_rejected() {
        // Two independent PKI bundles: each CA must reject the other's leaf certs.
        let a = generate_pki(&[]).expect("generate_pki failed");
        let b = generate_pki(&[]).expect("generate_pki failed");

        // Both CAs share the "openshell-ca" subject DN, so webpki may locate the
        // wrong anchor by name and then fail at signature verification
        // (`InvalidSignatureForPublicKey`) rather than reporting `UnknownIssuer`.
        // Either way the chain must be rejected; assert on the rejecting variants.
        let is_rejection = |e: &webpki::Error| {
            matches!(
                e,
                webpki::Error::UnknownIssuer | webpki::Error::InvalidSignatureForPublicKey
            )
        };

        let err = verify_chain(
            &a.server_cert_pem,
            &b.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::server_auth(),
        )
        .expect_err("server cert must not validate against an unrelated CA");
        assert!(
            is_rejection(&err),
            "unexpected error for wrong-CA server cert: {err:?}"
        );

        let err = verify_chain(
            &a.client_cert_pem,
            &b.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::client_auth(),
        )
        .expect_err("client cert must not validate against an unrelated CA");
        assert!(
            is_rejection(&err),
            "unexpected error for wrong-CA client cert: {err:?}"
        );

        // Sanity check: each leaf still validates against its *own* CA, proving the
        // rejection above is due to the mismatched issuer and not a broken chain.
        verify_chain(
            &a.server_cert_pem,
            &a.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::server_auth(),
        )
        .expect("server cert should validate against its own CA");
    }

    #[test]
    fn server_cert_valid_for_default_and_extra_sans() {
        let extra = "node-1.remote.example";
        let bundle = generate_pki(&[extra.to_string()]).expect("generate_pki failed");
        let leaf = cert_der(&bundle.server_cert_pem);
        let ee = EndEntityCert::try_from(&leaf).expect("leaf is not a valid certificate");

        // Default DNS, default IP, and the caller-supplied extra SAN must all match.
        for name in ["localhost", "host.docker.internal", "127.0.0.1", extra] {
            let server_name = ServerName::try_from(name).expect("test name should parse");
            ee.verify_is_valid_for_subject_name(&server_name)
                .unwrap_or_else(|e| panic!("cert should be valid for SAN {name}: {e:?}"));
        }
    }

    #[test]
    fn server_cert_rejects_name_not_in_sans() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");
        let leaf = cert_der(&bundle.server_cert_pem);
        let ee = EndEntityCert::try_from(&leaf).expect("leaf is not a valid certificate");

        let server_name =
            ServerName::try_from("not-a-listed-host.example").expect("test name should parse");
        let err = ee
            .verify_is_valid_for_subject_name(&server_name)
            .expect_err("cert must not be valid for a name absent from its SANs");
        assert!(matches!(err, webpki::Error::CertNotValidForName(_)));
    }

    #[test]
    fn extra_ip_san_is_present_on_server_cert() {
        let bundle = generate_pki(&["198.51.100.42".to_string()]).expect("generate_pki failed");
        let leaf = cert_der(&bundle.server_cert_pem);
        let ee = EndEntityCert::try_from(&leaf).expect("leaf is not a valid certificate");

        let ip = ServerName::try_from("198.51.100.42").expect("IP should parse");
        ee.verify_is_valid_for_subject_name(&ip)
            .expect("extra IP SAN should be present on the server certificate");
    }

    #[test]
    fn cert_validity_window_covers_now_and_future_but_not_before_start() {
        let bundle = generate_pki(&[]).expect("generate_pki failed");

        // rcgen's default validity is 1975-01-01 .. 4096-01-01, so "now" and a
        // far-future timestamp both fall inside the window.
        verify_chain(
            &bundle.server_cert_pem,
            &bundle.ca_cert_pem,
            UnixTime::now(),
            KeyUsage::server_auth(),
        )
        .expect("cert should be valid now");

        // ~year 3000 (well before not_after 4096, comfortably after not_before).
        let far_future = UnixTime::since_unix_epoch(Duration::from_secs(32_503_680_000));
        verify_chain(
            &bundle.server_cert_pem,
            &bundle.ca_cert_pem,
            far_future,
            KeyUsage::server_auth(),
        )
        .expect("cert should still be valid far in the future, before not_after");

        // 100 seconds after the Unix epoch (1970) precedes not_before (1975),
        // so validation must report the cert as not yet valid.
        let before_not_before = UnixTime::since_unix_epoch(Duration::from_secs(100));
        let err = verify_chain(
            &bundle.server_cert_pem,
            &bundle.ca_cert_pem,
            before_not_before,
            KeyUsage::server_auth(),
        )
        .expect_err("cert must not validate before its not_before");
        assert!(matches!(err, webpki::Error::CertNotValidYet { .. }));
    }
}
