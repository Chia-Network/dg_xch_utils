//! X.509 certificate construction for the Chia TLS identities.

use std::io;
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
use x509_cert::der::asn1::{Ia5String, OctetString};
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
const SERIAL_BYTES: usize = 16;
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

/// Builder profile for Chia identities. x509-cert's CABF and DevID profiles reject
/// names with OU and no C.
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

        let (ca, key_usage, san) = match &self.role {
            Role::Ca => (true, KeyUsages::KeyCertSign | KeyUsages::CRLSign, None),
            Role::Node(san) => (
                false,
                KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
                Some(san),
            ),
        };
        extensions.push(
            BasicConstraints {
                ca,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        extensions.push(KeyUsage(key_usage).to_extension(tbs.subject(), &extensions)?);
        if let Some(san) = san {
            extensions.push(san.to_extension(tbs.subject(), &extensions)?);
        }

        Ok(extensions)
    }
}

pub(super) fn issue_node(
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
    host: &str,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    super::validate_ssl_cert_and_key(ca_cert_pem, ca_key_pem)?;
    let ca_cert = Certificate::from_pem(ca_cert_pem).map_err(other)?;
    let ca_key = decode_ca_key(ca_key_pem)?;
    let issuer = ca_cert.tbs_certificate().subject().clone();
    let subject = Name::from_str(NODE_SUBJECT).map_err(other)?;
    let now = SystemTime::now();
    let not_before = now
        .checked_sub(ONE_DAY)
        .ok_or_else(|| io::Error::other("system clock is before the Unix epoch"))?;
    let validity = Validity::new(
        Time::try_from(not_before).map_err(other)?,
        NODE_NOT_AFTER.into(),
    );

    issue(
        Role::Node(subject_alt_names(host)?),
        subject,
        validity,
        Some((issuer, ca_key)),
    )
}

pub(super) fn issue_ca() -> io::Result<(Vec<u8>, Vec<u8>)> {
    let name = Name::from_str(CA_SUBJECT).map_err(other)?;
    let now = SystemTime::now();
    let not_after = now
        .checked_add(CA_LIFETIME)
        .ok_or_else(|| io::Error::other("system clock overflow"))?;
    let validity = Validity::new(
        CA_NOT_BEFORE.into(),
        Time::try_from(not_after).map_err(other)?,
    );

    issue(Role::Ca, name, validity, None)
}

/// `None` signs with the newly generated key (self-signed).
fn issue(
    role: Role,
    subject: Name,
    validity: Validity,
    issuer: Option<(Name, PrivateKey)>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = SysRng;
    let key = PrivateKey::new(&mut rng, RSA_KEY_BITS).map_err(other)?;
    let public_key = key.to_public_key();
    let spki = SubjectPublicKeyInfo::from_key(&public_key).map_err(other)?;
    let mut serial = [0u8; SERIAL_BYTES];
    rng.try_fill_bytes(&mut serial).map_err(other)?;
    serial[0] |= 0x01;
    let serial = SerialNumber::new(&serial).map_err(other)?;
    let key_pem = key.to_pkcs8_pem(LineEnding::default()).map_err(other)?;
    let (issuer, signing_key) = issuer.unwrap_or_else(|| (subject.clone(), key));
    let profile = ChiaProfile {
        issuer,
        subject,
        role,
    };
    let builder = CertificateBuilder::new(profile, serial, validity, spki).map_err(other)?;
    let signing_key = SigningKey::<Sha256>::new(signing_key);
    let certificate = builder
        .build::<_, rsa::pkcs1v15::Signature>(&signing_key)
        .map_err(other)?;
    let cert_pem = certificate.to_pem(LineEnding::default()).map_err(other)?;

    Ok((cert_pem.into_bytes(), key_pem.as_bytes().to_vec()))
}

fn decode_ca_key(pem: &[u8]) -> io::Result<PrivateKey> {
    let pem = String::from_utf8_lossy(pem);
    PrivateKey::from_pkcs1_pem(&pem)
        .or_else(|_| PrivateKey::from_pkcs8_pem(&pem))
        .map_err(|e| io::Error::other(format!("Failed to load Root Key: {e:?}")))
}

fn subject_alt_names(host: &str) -> io::Result<SubjectAltName> {
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

fn other(e: impl core::fmt::Debug) -> io::Error {
    io::Error::other(format!("{e:?}"))
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
    use std::sync::Arc;
    use x509_cert::der::asn1::{ObjectIdentifier, Utf8StringRef};
    use x509_cert::der::oid::AssociatedOid;
    use x509_cert::der::referenced::OwnedToRef;
    use x509_cert::der::{Encode, Tag, Tagged};
    use x509_cert::{AlgorithmIdentifier, Version};

    const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

    struct Expected {
        subject: [&'static str; 3],
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

    fn node_expected(san: Vec<GeneralName>) -> Expected {
        Expected {
            subject: ["Organic Farming Division", "Chia", "Chia"],
            ca: false,
            key_usage: KeyUsage(KeyUsages::DigitalSignature | KeyUsages::NonRepudiation),
            san: Some(san),
            not_before: Bound::Near(SystemTime::now() - Duration::from_secs(86_400)),
            not_after: Bound::Exact(
                DateTime::new(2049, 8, 2, 0, 0, 0).expect("valid node certificate expiry"),
            ),
        }
    }

    fn ca_expected() -> Expected {
        Expected {
            subject: ["Organic Farming Division", "Chia", "Chia CA"],
            ca: true,
            key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            san: None,
            not_before: Bound::Exact(
                DateTime::new(1970, 1, 1, 0, 0, 0).expect("valid CA certificate start"),
            ),
            not_after: Bound::Near(SystemTime::now() + Duration::from_secs(3650 * 86_400)),
        }
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
        assert_eq!(key.size(), 256);
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

    fn assert_subject(name: &Name, expected: [&str; 3]) {
        let rdns = name.as_ref().iter().collect::<Vec<_>>();
        assert_eq!(rdns.len(), expected.len());
        let oids = [
            ObjectIdentifier::new_unwrap("2.5.4.11"),
            ObjectIdentifier::new_unwrap("2.5.4.10"),
            ObjectIdentifier::new_unwrap("2.5.4.3"),
        ];
        for (rdn, (oid, expected_value)) in rdns.iter().zip(oids.iter().zip(expected)) {
            assert_eq!(rdn.len(), 1, "RDN must contain exactly one attribute");
            let attribute = rdn.iter().next().expect("RDN attribute");
            assert_eq!(attribute.oid, *oid);
            assert_eq!(attribute.value.tag(), Tag::Utf8String);
            let actual = Utf8StringRef::try_from(&attribute.value).expect("UTF-8 attribute value");
            assert_eq!(actual.as_str(), expected_value);
        }
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
        assert_eq!(serial_data.len(), 16);
        assert_ne!(serial_data[0], 0);

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
            issue_node(CHIA_CA_CRT.as_bytes(), CHIA_CA_KEY.as_bytes(), "chia.net")
                .expect("issue node certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            CHIA_CA_CRT.as_bytes(),
            node_expected(vec![dns_name("chia.net")]),
        );
    }

    #[test]
    fn private_ca_issues_a_valid_node_certificate() {
        let (ca_cert_pem, ca_key_pem) = issue_ca().expect("issue CA certificate");
        let (cert_pem, key_pem) =
            issue_node(&ca_cert_pem, &ca_key_pem, "chia.net").expect("issue node certificate");
        assert_certificate(
            &cert_pem,
            &key_pem,
            &ca_cert_pem,
            node_expected(vec![dns_name("chia.net")]),
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
            node_expected(vec![
                dns_name("localhost"),
                ip_name(&[127, 0, 0, 1]),
                ip_name(&std::net::Ipv6Addr::LOCALHOST.octets()),
            ]),
        );
    }

    #[test]
    fn generated_ca_certificate_is_self_signed() {
        let (cert_pem, key_pem) = issue_ca().expect("issue CA certificate");
        assert_certificate(&cert_pem, &key_pem, &cert_pem, ca_expected());
    }

    #[test]
    fn node_issuer_is_taken_from_the_ca_subject() {
        let (ca_cert_pem, ca_key_pem) = issue_ca().expect("issue CA certificate");
        let (node_cert_pem, node_key_pem) =
            issue_node(&ca_cert_pem, &ca_key_pem, "chia.net").expect("issue node certificate");
        let (child_cert_pem, _) =
            issue_node(&node_cert_pem, &node_key_pem, "chia.net").expect("issue child certificate");
        let node = parse(&node_cert_pem);
        let child = parse(&child_cert_pem);
        assert_eq!(
            child.tbs_certificate().issuer(),
            node.tbs_certificate().subject()
        );
        assert_ne!(
            child.tbs_certificate().issuer(),
            node.tbs_certificate().issuer()
        );
    }

    #[test]
    fn forged_certificate_naming_the_trusted_ca_fails_verification() {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs_from_bytes(CHIA_CA_CRT.as_bytes()).expect("load CA certificate") {
            roots.add(cert).expect("add trusted CA");
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .build()
        .expect("build client certificate verifier");

        let (cert_pem, _) = issue_node(CHIA_CA_CRT.as_bytes(), CHIA_CA_KEY.as_bytes(), "chia.net")
            .expect("issue node certificate");
        let cert_der = load_certs_from_bytes(&cert_pem).expect("load node certificate");
        verifier
            .verify_client_cert(&cert_der[0], &[], rustls::pki_types::UnixTime::now())
            .expect("trusted node certificate must verify");

        let ca_cert = parse(CHIA_CA_CRT.as_bytes());
        let subject = Name::from_str(NODE_SUBJECT).expect("parse node subject");
        let not_before = SystemTime::now()
            .checked_sub(ONE_DAY)
            .expect("system clock after Unix epoch");
        let validity = Validity::new(
            Time::try_from(not_before).expect("encode not before"),
            NODE_NOT_AFTER.into(),
        );
        let unrelated_key =
            PrivateKey::new(&mut SysRng, RSA_KEY_BITS).expect("generate unrelated key");
        let (forged_pem, _) = issue(
            Role::Node(subject_alt_names("chia.net").expect("subject alt names")),
            subject,
            validity,
            Some((ca_cert.tbs_certificate().subject().clone(), unrelated_key)),
        )
        .expect("issue forged certificate");
        let forged = parse(&forged_pem);
        assert_eq!(
            forged.tbs_certificate().issuer(),
            ca_cert.tbs_certificate().subject()
        );

        let forged_der = load_certs_from_bytes(&forged_pem).expect("load forged certificate");
        let error = verifier
            .verify_client_cert(&forged_der[0], &[], rustls::pki_types::UnixTime::now())
            .expect_err("forged certificate must fail verification");
        assert_eq!(
            error,
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        );
    }

    #[test]
    fn mismatched_ca_key_is_rejected() {
        let (_, ca_key_pem) = issue_ca().expect("issue CA certificate");
        let error = issue_node(CHIA_CA_CRT.as_bytes(), &ca_key_pem, "chia.net")
            .expect_err("mismatched CA key must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
