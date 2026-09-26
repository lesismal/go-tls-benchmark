//! The client's side of TLS, set up as benchcli-go's crypto/tls one is: the
//! one version the framework is pinned to, no session resumption, so that
//! every handshake is a full one, and no check of the server's certificate
//! chain - the benchmark measures the server's side of the handshake - while
//! the handshake's signatures are still verified with the certificate's key,
//! as crypto/tls's InsecureSkipVerify still verifies them.

use std::sync::Arc;

use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion,
    SignatureScheme,
};

/// aws-lc-rs's provider with AES-128-GCM first, as crypto/tls orders it on a
/// machine with AES instructions, rather than AES-256-GCM, as rustls does: the
/// servers pick from the client's order, and this makes a rustls client get
/// the suite a crypto/tls one gets. frameworks/rustls orders its own the same
/// way.
pub fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    let rank = |s: CipherSuite| match s {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
        CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 3,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 4,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 5,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 6,
        _ => 7,
    };
    p.cipher_suites.sort_by_key(|s| rank(s.suite()));
    p
}

/// The client configuration for a framework pinned to version, "1.2" or
/// "1.3"; rustls speaks no other.
pub fn client_config(version: &str) -> Result<ClientConfig, String> {
    let version = match version {
        "1.2" => &rustls::version::TLS12,
        "1.3" => &rustls::version::TLS13,
        v => return Err(format!("rustls does not implement TLS {v}")),
    };
    let provider = Arc::new(provider());
    let verifier = Arc::new(SkipChain(provider.signature_verification_algorithms));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    Ok(config)
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(crate::config::SERVER_NAME).expect("a valid DNS name")
}

#[derive(Debug)]
struct SkipChain(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for SkipChain {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// What a handshake negotiated, in the names crypto/tls gives it, so that a
/// report this client wrote reads like one benchcli-go wrote.
#[derive(Clone, Debug)]
pub struct Params {
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: String,
    pub cert_key: String,
}

impl Default for Params {
    fn default() -> Self {
        let dash = || "-".to_string();
        Params {
            version: dash(),
            cipher_suite: dash(),
            key_exchange: dash(),
            cert_key: dash(),
        }
    }
}

pub fn params(conn: &ClientConnection) -> Params {
    let mut p = Params::default();
    if let Some(v) = conn.protocol_version() {
        p.version = match v {
            ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
            ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
            other => format!("{other:?}"),
        };
    }
    if let Some(s) = conn.negotiated_cipher_suite() {
        p.cipher_suite = suite_name(s.suite());
    }
    if let Some(g) = conn.negotiated_key_exchange_group() {
        p.key_exchange = group_name(&format!("{:?}", g.name()));
    }
    if let Some(cert) = conn.peer_certificates().and_then(|c| c.first()) {
        p.cert_key = key_name(cert.as_ref());
    }
    p
}

/// tls.CipherSuiteName: the IANA name, which rustls also uses but for the
/// TLS 1.3 suites, which it prefixes TLS13_ rather than TLS_.
fn suite_name(s: CipherSuite) -> String {
    let name = format!("{s:?}");
    match name.strip_prefix("TLS13_") {
        Some(rest) => format!("TLS_{rest}"),
        None => name,
    }
}

/// tls.CurveID.String: crypto/tls names the NIST curves CurveP256 and so on.
fn group_name(name: &str) -> String {
    match name {
        "secp256r1" => "CurveP256".into(),
        "secp384r1" => "CurveP384".into(),
        "secp521r1" => "CurveP521".into(),
        other => other.into(),
    }
}

/// certs.KeyName: the certificate's key as -key names its type, with its
/// size, e.g. "ecdsa-p256", "rsa-2048" or "ed25519", read out of its
/// SubjectPublicKeyInfo.
pub fn key_name(cert: &[u8]) -> String {
    spki(cert)
        .and_then(|(alg, key)| name_key(alg, key))
        .unwrap_or_else(|| "-".into())
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

fn name_key(alg: &[u8], key: &[u8]) -> Option<String> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }
    let (oid, params) = der_next(alg)?;
    let oid = expect(oid, 0x06)?;
    if oid == OID_EC_PUBLIC_KEY {
        let curve = expect(der_next(params)?.0, 0x06)?;
        let bits = match curve {
            c if c == OID_P256 => 256,
            c if c == OID_P384 => 384,
            c if c == OID_P521 => 521,
            _ => return Some("ecdsa".into()),
        };
        return Some(format!("ecdsa-p{bits}"));
    }
    if oid == OID_RSA {
        // The key is a BIT STRING - one byte of unused bits first - holding
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
        let rsa = expect(der_next(key.get(1..)?)?.0, 0x30)?;
        let mut n = expect(der_next(rsa)?.0, 0x02)?;
        while n.first() == Some(&0) {
            n = &n[1..];
        }
        let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
        return Some(format!("rsa-{bits}"));
    }
    if oid == OID_ED25519 {
        return Some("ed25519".into());
    }
    None
}

/// Certificate ::= SEQUENCE { tbsCertificate, ... }, whose TBSCertificate
/// holds, after an optional [0] version, the serial number, signature,
/// issuer, validity and subject, the SubjectPublicKeyInfo: its
/// AlgorithmIdentifier and its key's BIT STRING contents.
fn spki(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let cert = expect(der_next(cert)?.0, 0x30)?;
    let mut tbs = expect(der_next(cert)?.0, 0x30)?;
    if tbs.first() == Some(&0xa0) {
        tbs = der_next(tbs)?.1;
    }
    for _ in 0..5 {
        tbs = der_next(tbs)?.1;
    }
    let spki = expect(der_next(tbs)?.0, 0x30)?;
    let (alg, rest) = der_next(spki)?;
    let key = expect(der_next(rest)?.0, 0x03)?;
    Some((expect(alg, 0x30)?, key))
}

/// One DER element off the front of data: the element, tag included, and
/// what follows it.
fn der_next(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *data.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let len = data
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |acc, &b| acc << 8 | b as usize);
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    (end <= data.len()).then(|| (&data[..end], &data[end..]))
}

/// The contents of element, which has to carry tag.
fn expect(element: &[u8], tag: u8) -> Option<&[u8]> {
    if *element.first()? != tag {
        return None;
    }
    let first = element[1] as usize;
    let header = if first < 0x80 { 2 } else { 2 + (first & 0x7f) };
    element.get(header..)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_like_crypto_tls() {
        assert_eq!(
            suite_name(CipherSuite::TLS13_AES_128_GCM_SHA256),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(
            suite_name(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(group_name("secp256r1"), "CurveP256");
        assert_eq!(group_name("X25519MLKEM768"), "X25519MLKEM768");
    }

    #[test]
    fn aes_128_first() {
        let p = provider();
        assert_eq!(
            p.cipher_suites[0].suite(),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );
    }

    #[test]
    fn tls11_refused() {
        assert!(client_config("1.1").is_err());
        assert!(client_config("1.2").is_ok());
        assert!(client_config("1.3").is_ok());
    }

    /// Every key -key takes, as the servers issue their certificates.
    #[test]
    fn key_names() {
        for (alg, want) in [
            (&rcgen::PKCS_ECDSA_P256_SHA256, "ecdsa-p256"),
            (&rcgen::PKCS_ECDSA_P384_SHA384, "ecdsa-p384"),
            (&rcgen::PKCS_ED25519, "ed25519"),
            (&rcgen::PKCS_RSA_SHA256, "rsa-2048"),
        ] {
            let pair = if want.starts_with("rsa") {
                rcgen::KeyPair::generate_rsa_for(alg, rcgen::RsaKeySize::_2048)
            } else {
                rcgen::KeyPair::generate_for(alg)
            }
            .unwrap();
            let params = rcgen::CertificateParams::new(vec!["go-tls-benchmark".into()]).unwrap();
            let cert = params.self_signed(&pair).unwrap();
            assert_eq!(key_name(cert.der()), want);
        }
        assert_eq!(key_name(b"not a certificate"), "-");
    }

    #[test]
    fn der_lengths() {
        assert_eq!(
            der_next(&[0x02, 0x01, 0x05, 0xff]),
            Some((&[0x02, 0x01, 0x05][..], &[0xff][..]))
        );
        assert_eq!(der_next(&[0x02, 0x05, 0x00]), None);
        assert_eq!(expect(&[0x02, 0x01, 0x05], 0x02), Some(&[0x05][..]));
        assert_eq!(expect(&[0x02, 0x01, 0x05], 0x30), None);
    }
}
