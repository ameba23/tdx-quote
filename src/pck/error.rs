use core::{
    array::TryFromSliceError,
    fmt::{self, Display},
};

/// An error when parsing or verifying a PCK or provider certificate
#[derive(Debug, PartialEq, Eq)]
pub enum PckParseVerifyError {
    Parse,
    Verify,
    BadPublicKey,
    NoCertificate,
    Pem,
}

impl Display for PckParseVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PckParseVerifyError::Parse => f.write_str("Cannot parse PCK certificate"),
            PckParseVerifyError::Verify => f.write_str("Cannot verify PCK certificate"),
            PckParseVerifyError::BadPublicKey => f.write_str("Bad public key"),
            PckParseVerifyError::NoCertificate => f.write_str("No certificate chain given"),
            PckParseVerifyError::Pem => f.write_str("Unable to decode PEM"),
        }
    }
}

impl From<spki::der::Error> for PckParseVerifyError {
    fn from(_: spki::der::Error) -> PckParseVerifyError {
        PckParseVerifyError::Parse
    }
}

impl From<x509_verify::Error> for PckParseVerifyError {
    fn from(_: x509_verify::Error) -> PckParseVerifyError {
        PckParseVerifyError::Verify
    }
}

impl From<TryFromSliceError> for PckParseVerifyError {
    fn from(_: TryFromSliceError) -> PckParseVerifyError {
        PckParseVerifyError::BadPublicKey
    }
}

impl From<pem::PemError> for PckParseVerifyError {
    fn from(_: pem::PemError) -> PckParseVerifyError {
        PckParseVerifyError::Pem
    }
}
