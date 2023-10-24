extern crate openssl;

use openssl::pkey;
use openssl::rsa::Rsa;
use pyo3::prelude::*;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;
use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(rsmime, ReadCertificateError, PyException);
create_exception!(rsmime, LoadCertificateError, PyException);
create_exception!(rsmime, SignError, PyException);

pub fn _sign(cert_file: &str, key_file: &str, data_to_sign: &[u8]) -> PyResult<Vec<u8>> {
    let certs = Stack::new().expect("Failed to create stack");

    if data_to_sign.is_empty() {
        return Err(SignError::new_err("Cannot sign empty data"));
    }
    
    let cert_data = std::fs::read(cert_file).map_err(|err| ReadCertificateError::new_err(err.to_string()))?;
    let key_data = std::fs::read(key_file).map_err(|err| ReadCertificateError::new_err(err.to_string()))?;

    let cert = X509::from_pem(&cert_data).map_err(|err| LoadCertificateError::new_err(err.to_string()))?;
    let rsa = Rsa::private_key_from_pem(&key_data).map_err(|err| LoadCertificateError::new_err(err.to_string()))?;
    let pkey = pkey::PKey::from_rsa(rsa).map_err(|err| LoadCertificateError::new_err(err.to_string()))?;

    let flags = Pkcs7Flags::STREAM;
    let pkcs7 = Pkcs7::sign(cert.as_ref(), pkey.as_ref(), certs.as_ref(), data_to_sign, flags).map_err(|err| SignError::new_err(err.to_string()))?;
    let encrypted = pkcs7.to_smime(data_to_sign, flags).map_err(|err| SignError::new_err(err.to_string()))?;

    Ok(encrypted)
}

#[pyfunction]
fn sign(cert_file: &str, key_file: &str, data_to_sign: Vec<u8>) -> PyResult<String> {
    match _sign(cert_file, key_file, &data_to_sign) {
        Ok(signed_data) => {
            match String::from_utf8(signed_data) {
                Ok(signed_string) => Ok(signed_string),
                Err(err) => Err(PyException::new_err(err))
            }
        },
        Err(err) => Err(PyException::new_err(err.to_string())),
    }
}

#[pymodule]
fn rsmime(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("ReadCertificateError", py.get_type::<ReadCertificateError>())?;
    m.add("LoadCertificateError", py.get_type::<LoadCertificateError>())?;
    m.add("SignError", py.get_type::<SignError>())?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    Ok(())
}
