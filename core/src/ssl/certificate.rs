//! X.509 certificate construction for the Chia TLS identities.

use std::io::Error;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use rand::TryRng;
use rand::rngs::SysRng;
use rsa::PrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::sha2::Sha256;
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::der::asn1::{Ia5String, OctetString, UtcTime};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{DateTime, DecodePem, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectAltName,
    SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

const RSA_KEY_BITS: usize = 2048;
const CA_SUBJECT: &str = "CN=Chia CA,O=Chia,OU=Organic Farming Division";
const NODE_SUBJECT: &str = "CN=Chia,O=Chia,OU=Organic Farming Division";
pub(super) const DEFAULT_HOST: &str = "chia.net";
const NODE_NOT_AFTER: DateTime = match DateTime::new(2049, 8, 2, 0, 0, 0) {
    Ok(date) => date,
    Err(_) => panic!("invalid fixed node certificate expiry"),
};
const CA_NOT_BEFORE: DateTime = match DateTime::new(1970, 1, 1, 0, 0, 0) {
    Ok(date) => date,
    Err(_) => panic!("invalid fixed CA certificate start date"),
};
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);
const CA_LIFETIME: Duration = Duration::from_secs(3650 * 24 * 60 * 60);

/// Minimal profile because x509-cert's CABF and DevID profiles reject our
/// names (they use OU without C), which requires a custom profile.
struct ChiaProfile {
    issuer: Name,
    subject: Name,
    role: Role,
}

enum Role {
    Ca,
    Node(SubjectAltName),
}

impl BuilderProfile for ChiaProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = Vec::new();
        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(tbs.subject(), &extensions)?);
        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk)?
                .to_extension(tbs.subject(), &extensions)?,
        );

        let (ca, key_usage) = match &self.role {
            Role::Ca => (true, KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
            Role::Node(_) => (
                false,
                KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
            ),
        };
        extensions.push(
            BasicConstraints {
                ca,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(key_usage.to_extension(tbs.subject(), &extensions)?);

        if let Role::Node(san) = &self.role {
            extensions.push(san.to_extension(tbs.subject(), &extensions)?);
        }

        Ok(extensions)
    }
}

pub(super) fn issue_node(
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
    host: &str,
) -> Result<(Vec<u8>, Vec<u8>), std::io::Error> {
    let ca_cert = Certificate::from_pem(ca_cert_pem).map_err(other)?;
    let ca_key = decode_ca_key(ca_key_pem)?;
    let issuer = ca_cert.tbs_certificate().subject().clone();
    let subject = Name::from_str(NODE_SUBJECT).map_err(other)?;
    let now = SystemTime::now();
    let not_before = now
        .checked_sub(ONE_DAY)
        .ok_or_else(|| Error::other("system clock is before the Unix epoch"))?;
    let validity = Validity::new(utc_system_time(not_before)?, utc_date_time(NODE_NOT_AFTER)?);

    issue(
        Role::Node(subject_alt_names(host)?),
        issuer,
        subject,
        validity,
        Some(ca_key),
    )
}

pub(super) fn issue_ca() -> Result<(Vec<u8>, Vec<u8>), std::io::Error> {
    let name = Name::from_str(CA_SUBJECT).map_err(other)?;
    let now = SystemTime::now();
    let not_after = now
        .checked_add(CA_LIFETIME)
        .ok_or_else(|| Error::other("system clock overflow"))?;
    let validity = Validity::new(utc_date_time(CA_NOT_BEFORE)?, utc_system_time(not_after)?);

    issue(Role::Ca, name.clone(), name, validity, None)
}

fn issue(
    role: Role,
    issuer: Name,
    subject: Name,
    validity: Validity,
    issuer_key: Option<PrivateKey>,
) -> Result<(Vec<u8>, Vec<u8>), std::io::Error> {
    let mut rng = SysRng;
    let key = PrivateKey::new(&mut rng, RSA_KEY_BITS).map_err(other)?;
    let public_key = key.to_public_key();
    let spki = SubjectPublicKeyInfo::from_key(&public_key).map_err(other)?;
    let serial = SerialNumber::from(rng.try_next_u32().map_err(other)?);
    let profile = ChiaProfile {
        issuer,
        subject,
        role,
    };
    let builder = CertificateBuilder::new(profile, serial, validity, spki).map_err(other)?;
    let key_pem = key.to_pkcs8_pem(LineEnding::default()).map_err(other)?;
    let signing_key = SigningKey::<Sha256>::new(issuer_key.unwrap_or(key));
    let certificate = builder
        .build::<_, rsa::pkcs1v15::Signature>(&signing_key)
        .map_err(other)?;
    let cert_pem = certificate.to_pem(LineEnding::default()).map_err(other)?;

    Ok((cert_pem.into_bytes(), key_pem.as_bytes().to_vec()))
}

fn decode_ca_key(pem: &[u8]) -> Result<PrivateKey, std::io::Error> {
    let pem = String::from_utf8_lossy(pem);
    PrivateKey::from_pkcs1_pem(&pem)
        .or_else(|_| PrivateKey::from_pkcs8_pem(&pem))
        .map_err(|e| Error::other(format!("Failed to load Root Key: {e:?}")))
}

fn subject_alt_names(host: &str) -> Result<SubjectAltName, std::io::Error> {
    let mut names = vec![GeneralName::DnsName(Ia5String::new(host).map_err(other)?)];
    if host == "localhost" {
        names.push(GeneralName::IpAddress(
            OctetString::new([127, 0, 0, 1]).map_err(other)?,
        ));
        names.push(GeneralName::IpAddress(
            OctetString::new(std::net::Ipv6Addr::LOCALHOST.octets()).map_err(other)?,
        ));
    }
    Ok(SubjectAltName(names))
}

fn utc_date_time(time: DateTime) -> Result<Time, std::io::Error> {
    Ok(Time::UtcTime(UtcTime::from_date_time(time).map_err(other)?))
}

fn utc_system_time(time: SystemTime) -> Result<Time, std::io::Error> {
    Ok(Time::UtcTime(
        UtcTime::from_system_time(time).map_err(other)?,
    ))
}

fn other(e: impl core::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CHIA_CA_CRT, CHIA_CA_KEY};
    use crate::ssl::{
        load_certs_from_bytes, load_private_key_from_bytes, validate_ssl_cert_and_key,
    };
    use rsa::PublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::traits::PublicKeyParts;
    use x509_cert::der::Encode;
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::der::oid::AssociatedOid;
    use x509_cert::der::referenced::OwnedToRef;
    use x509_cert::{AlgorithmIdentifier, Version};

    const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    struct Expected {
        subject: &'static str,
        ca: bool,
        key_usage: KeyUsage,
        san: Option<Vec<GeneralName>>,
        not_before: Bound,
        not_after: Bound,
    }

    enum Bound {
        Exact(DateTime),
        Near(SystemTime),
    }

    fn parse(pem: &[u8]) -> Certificate {
        Certificate::from_pem(pem).expect("parse certificate")
    }

    fn public_key(cert: &Certificate) -> PublicKey {
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("encode subject public key info");
        PublicKey::from_public_key_der(&spki).expect("parse RSA public key")
    }

    fn verify_signature(cert: &Certificate, issuer_key: &PublicKey) {
        let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(issuer_key.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(
            cert.signature()
                .as_bytes()
                .expect("signature is byte-aligned"),
        )
        .expect("parse RSA signature");
        let tbs = cert.tbs_certificate().to_der().expect("encode tbs");
        key.verify(&tbs, &signature).expect("verify signature");
    }

    fn assert_rsa_public_key(key: &PublicKey) {
        assert_eq!(key.size(), RSA_KEY_BITS / 8);
        assert_eq!(key.e_bytes().as_ref(), &[1, 0, 1]);
    }

    fn assert_sha256_with_rsa(algorithm: &AlgorithmIdentifier) {
        assert_eq!(algorithm.oid, SHA256_WITH_RSA);
        assert_eq!(
            algorithm.parameters,
            Some(x509_cert::der::asn1::Any::null())
        );
    }

    fn assert_utc(time: Time) {
        assert!(matches!(time, Time::UtcTime(_)));
    }

    fn assert_close(actual: SystemTime, expected: SystemTime, tolerance: Duration) {
        let difference = actual
            .duration_since(expected)
            .or_else(|_| expected.duration_since(actual))
            .expect("SystemTime difference");
        assert!(difference <= tolerance);
    }

    fn assert_bound(bound: Bound, actual: Time) {
        assert_utc(actual);
        match bound {
            Bound::Exact(expected) => assert_eq!(actual.to_date_time(), expected),
            Bound::Near(expected) => {
                assert_close(actual.to_system_time(), expected, Duration::from_secs(120))
            }
        }
    }

    fn assert_subject(name: &Name, subject: &str) {
        assert_eq!(name.to_string(), subject);
        let mut expected = subject.split(',').collect::<Vec<_>>();
        expected.reverse();
        let actual = name
            .as_ref()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    fn assert_extension_order(cert: &Certificate, expected: &[ObjectIdentifier]) {
        let actual = cert
            .tbs_certificate()
            .extensions()
            .expect("extensions")
            .iter()
            .map(|extension| extension.extn_id)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    fn dns_name(name: &str) -> GeneralName {
        GeneralName::DnsName(Ia5String::new(name).expect("IA5 DNS name"))
    }

    fn ip_name(bytes: &[u8]) -> GeneralName {
        GeneralName::IpAddress(OctetString::new(bytes).expect("IP address"))
    }

    fn assert_certificate(cert_pem: &[u8], key_pem: &[u8], issuer_pem: &[u8], expected: Expected) {
        let cert = parse(cert_pem);
        let issuer = parse(issuer_pem);
        let tbs = cert.tbs_certificate();

        assert_eq!(tbs.version(), Version::V3);
        assert_sha256_with_rsa(tbs.signature());
        assert_sha256_with_rsa(cert.signature_algorithm());
        assert_eq!(tbs.signature(), cert.signature_algorithm());

        assert_eq!(tbs.issuer(), issuer.tbs_certificate().subject());
        assert_subject(tbs.subject(), expected.subject);

        let issuer_key = public_key(&issuer);
        verify_signature(&cert, &issuer_key);

        let cert_key = public_key(&cert);
        assert_rsa_public_key(&cert_key);

        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        let private_key = PrivateKey::from_pkcs8_pem(&String::from_utf8_lossy(key_pem))
            .expect("parse PKCS#8 private key");
        assert_eq!(private_key.to_public_key(), cert_key);

        let validity = tbs.validity();
        assert_bound(expected.not_before, validity.not_before);
        assert_bound(expected.not_after, validity.not_after);

        let serial = tbs.serial_number().as_bytes();
        let serial_data = serial.strip_prefix(&[0]).unwrap_or(serial);
        assert!(!serial_data.is_empty());
        assert!(serial_data.len() <= 4);
        let serial_value = serial_data
            .iter()
            .fold(0u32, |value, &byte| (value << 8) | u32::from(byte));
        assert!(serial_value > 0);

        let mut extension_order = vec![
            SubjectKeyIdentifier::OID,
            AuthorityKeyIdentifier::OID,
            BasicConstraints::OID,
            KeyUsage::OID,
        ];
        if expected.san.is_some() {
            extension_order.push(SubjectAltName::OID);
        }
        assert_extension_order(&cert, &extension_order);

        let (critical, ski) = tbs
            .get_extension::<SubjectKeyIdentifier>()
            .expect("decode SKI")
            .expect("SKI present");
        assert!(!critical);
        let cert_spki = tbs.subject_public_key_info().owned_to_ref();
        assert_eq!(ski, SubjectKeyIdentifier::try_from(cert_spki).expect("SKI"));

        let (critical, aki) = tbs
            .get_extension::<AuthorityKeyIdentifier>()
            .expect("decode AKI")
            .expect("AKI present");
        assert!(!critical);
        let issuer_spki = issuer
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();
        let issuer_ski = SubjectKeyIdentifier::try_from(issuer_spki).expect("issuer SKI");
        assert_eq!(aki.key_identifier, Some(issuer_ski.0));
        assert!(aki.authority_cert_issuer.is_none());
        assert!(aki.authority_cert_serial_number.is_none());

        let (critical, constraints) = tbs
            .get_extension::<BasicConstraints>()
            .expect("decode BasicConstraints")
            .expect("BasicConstraints present");
        assert!(critical);
        assert_eq!(constraints.ca, expected.ca);
        assert_eq!(constraints.path_len_constraint, None);

        let (critical, key_usage) = tbs
            .get_extension::<KeyUsage>()
            .expect("decode KeyUsage")
            .expect("KeyUsage present");
        assert!(critical);
        assert_eq!(key_usage, expected.key_usage);

        if let Some(expected_san) = expected.san {
            let (critical, san) = tbs
                .get_extension::<SubjectAltName>()
                .expect("decode SAN")
                .expect("SAN present");
            assert!(!critical);
            assert_eq!(san.0, expected_san);
        }

        assert_eq!(
            load_certs_from_bytes(cert_pem).expect("load certs").len(),
            1
        );
        assert!(load_private_key_from_bytes(key_pem).is_ok());
        validate_ssl_cert_and_key(cert_pem, key_pem).expect("valid SSL pair for rustls");
    }

    #[test]
    fn bundled_public_ca_issues_a_valid_node_certificate() {
        let (cert_pem, key_pem) =
            issue_node(CHIA_CA_CRT.as_bytes(), CHIA_CA_KEY.as_bytes(), DEFAULT_HOST)
                .expect("issue node certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            CHIA_CA_CRT.as_bytes(),
            Expected {
                subject: NODE_SUBJECT,
                ca: false,
                key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
                san: Some(vec![dns_name(DEFAULT_HOST)]),
                not_before: Bound::Near(SystemTime::now() - ONE_DAY),
                not_after: Bound::Exact(NODE_NOT_AFTER),
            },
        );
    }

    #[test]
    fn private_ca_issues_a_valid_node_certificate() {
        let (ca_cert_pem, ca_key_pem) = issue_ca().expect("issue CA certificate");
        let (cert_pem, key_pem) =
            issue_node(&ca_cert_pem, &ca_key_pem, DEFAULT_HOST).expect("issue node certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            &ca_cert_pem,
            Expected {
                subject: NODE_SUBJECT,
                ca: false,
                key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
                san: Some(vec![dns_name(DEFAULT_HOST)]),
                not_before: Bound::Near(SystemTime::now() - ONE_DAY),
                not_after: Bound::Exact(NODE_NOT_AFTER),
            },
        );
    }

    #[test]
    fn localhost_node_certificate_has_loopback_addresses() {
        let (cert_pem, key_pem) =
            issue_node(CHIA_CA_CRT.as_bytes(), CHIA_CA_KEY.as_bytes(), "localhost")
                .expect("issue localhost certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            CHIA_CA_CRT.as_bytes(),
            Expected {
                subject: NODE_SUBJECT,
                ca: false,
                key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
                san: Some(vec![
                    dns_name("localhost"),
                    ip_name(&[127, 0, 0, 1]),
                    ip_name(&std::net::Ipv6Addr::LOCALHOST.octets()),
                ]),
                not_before: Bound::Near(SystemTime::now() - ONE_DAY),
                not_after: Bound::Exact(NODE_NOT_AFTER),
            },
        );
    }

    #[test]
    fn generated_ca_certificate_is_self_signed() {
        let (cert_pem, key_pem) = issue_ca().expect("issue CA certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            &cert_pem,
            Expected {
                subject: CA_SUBJECT,
                ca: true,
                key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
                san: None,
                not_before: Bound::Exact(CA_NOT_BEFORE),
                not_after: Bound::Near(SystemTime::now() + CA_LIFETIME),
            },
        );
    }

    #[test]
    fn garbage_ca_key_reports_root_key_context() {
        let error = issue_node(CHIA_CA_CRT.as_bytes(), b"not a private key", DEFAULT_HOST)
            .expect_err("garbage CA key must be rejected");
        assert!(error.to_string().starts_with("Failed to load Root Key: "));
    }
}
