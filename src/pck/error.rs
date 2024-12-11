use core::array::TryFromSliceError;

/// An error when parsing or verifying a PCK or provider certificate
#[derive(Debug)]
pub enum PckParseVerifyError {
    Parse,
    Verify,
    BadPublicKey,
    NoCertificate,
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
