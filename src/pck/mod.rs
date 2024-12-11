mod error;

use alloc::vec::Vec;
pub use error::PckParseVerifyError;
use x509_verify::{
    der::{Decode, Encode},
    x509_cert::Certificate,
    Signature, VerifyInfo, VerifyingKey,
};

/// Intels root CA certificate in DER format available from here:
/// https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer
/// Valid until December 31 2049
const INTEL_ROOT_CA_DER: &[u8; 659] =
    include_bytes!("Intel_SGX_Provisioning_Certification_RootCA.cer");

/// Verify a PCK certificate chain against Intel root CA
/// given as PEM certificated concatenated together.
pub fn verify_pck_certificate_chain_pem(
    pck_certificate_chain_pem: Vec<u8>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    let pems = pem::parse_many(pck_certificate_chain_pem).unwrap();
    let ders = pems
        .into_iter()
        .map(|pem| pem.contents().to_vec())
        .collect();
    verify_pck_certificate_chain_der(ders)
}

/// Verify a PCK certificate chain against Intel root CA
/// given as a vector of der encoded certificates
pub fn verify_pck_certificate_chain_der(
    pck_certificate_chain_der: Vec<Vec<u8>>,
) -> Result<p256::ecdsa::VerifyingKey, PckParseVerifyError> {
    let pck_uncompressed = verify_pck_cert_chain(pck_certificate_chain_der)?;

    // Compress / convert public key
    let point = p256::EncodedPoint::from_bytes(pck_uncompressed)
        .map_err(|_| PckParseVerifyError::BadPublicKey)?;
    let pck_verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|_| PckParseVerifyError::BadPublicKey)?;
    Ok(pck_verifying_key)
}

/// Validate PCK and provider certificates and if valid return the PCK
fn verify_pck_cert_chain(certificates_der: Vec<Vec<u8>>) -> Result<[u8; 65], PckParseVerifyError> {
    if certificates_der.is_empty() {
        return Err(PckParseVerifyError::NoCertificate);
    }

    // Parse the certificates
    let mut certificates = Vec::new();
    for certificate in certificates_der {
        certificates.push(Certificate::from_der(&certificate)?);
    }
    // Add the root certificate to the end of the chain. Since the root cert is self-signed, this
    // will work regardless of whether the user has included this certicate in the chain or not
    certificates.push(Certificate::from_der(INTEL_ROOT_CA_DER)?);

    // Verify the certificate chain
    for i in 0..certificates.len() {
        let verifying_key: &VerifyingKey = if i + 1 == certificates.len() {
            &certificates[i]
                .tbs_certificate
                .subject_public_key_info
                .clone()
                .try_into()?
        } else {
            &certificates[i + 1]
                .tbs_certificate
                .subject_public_key_info
                .clone()
                .try_into()?
        };
        verify_cert(&certificates[i], verifying_key)?;
    }

    // Get the first certificate
    let pck_key = &certificates
        .first()
        .ok_or(PckParseVerifyError::NoCertificate)?
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;

    Ok(pck_key
        .as_bytes()
        .ok_or(PckParseVerifyError::BadPublicKey)?
        .try_into()?)
}

/// Given a cerificate and a public key, verify the certificate
fn verify_cert(subject: &Certificate, issuer_pk: &VerifyingKey) -> Result<(), PckParseVerifyError> {
    let verify_info = VerifyInfo::new(
        subject.tbs_certificate.to_der()?.into(),
        Signature::new(
            &subject.signature_algorithm,
            subject
                .signature
                .as_bytes()
                .ok_or(PckParseVerifyError::Parse)?,
        ),
    );
    Ok(issuer_pk.verify(&verify_info)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_verify_pck_cert_chain() {
        let pck = include_bytes!("../../test_pck_certs/pck_cert.der").to_vec();
        let platform = include_bytes!("../../test_pck_certs/platform_pcs_cert.der").to_vec();
        assert!(verify_pck_certificate_chain_der(vec![pck, platform]).is_ok());
    }
}
