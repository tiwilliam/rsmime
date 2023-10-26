extern crate openssl;

use std::io::{Error, ErrorKind};

use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey;
use openssl::rsa::Rsa;
use openssl::stack::{Stack, StackRef};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509Ref, X509};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

create_exception!(rsmime, CertificateError, PyException);
create_exception!(rsmime, SignError, PyException);
create_exception!(rsmime, VerifyError, PyException);

fn _sign(
    cert_file: &str,
    key_file: &str,
    data_to_sign: &[u8],
    detached: bool,
) -> PyResult<Vec<u8>> {
    let certs = Stack::new().unwrap();

    if data_to_sign.is_empty() {
        return Err(SignError::new_err("Cannot sign empty data"));
    }

    let cert_data =
        std::fs::read(cert_file).map_err(|err| CertificateError::new_err(err.to_string()))?;
    let key_data =
        std::fs::read(key_file).map_err(|err| CertificateError::new_err(err.to_string()))?;

    let cert =
        X509::from_pem(&cert_data).map_err(|err| CertificateError::new_err(err.to_string()))?;
    let rsa = Rsa::private_key_from_pem(&key_data)
        .map_err(|err| CertificateError::new_err(err.to_string()))?;
    let pkey =
        pkey::PKey::from_rsa(rsa).map_err(|err| CertificateError::new_err(err.to_string()))?;

    let flags = if detached {
        Pkcs7Flags::DETACHED
    } else {
        Pkcs7Flags::empty()
    };

    let pkcs7 = Pkcs7::sign(
        cert.as_ref(),
        pkey.as_ref(),
        certs.as_ref(),
        data_to_sign,
        flags,
    )
    .map_err(|err| SignError::new_err(err.to_string()))?;
    let out = pkcs7
        .to_smime(data_to_sign, flags)
        .map_err(|err| SignError::new_err(err.to_string()))?;

    Ok(out)
}

fn cert_subject_to_string(cert: &X509Ref, nid: Nid) -> String {
    let nid_entry = cert.subject_name().entries_by_nid(nid).next().unwrap();
    nid_entry.data().as_utf8().unwrap().to_string()
}

fn validate_expiry(certs: &StackRef<X509>) -> Result<(), Error> {
    for cert in certs.iter() {
        let expire = cert.not_after();
        if expire.le(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()) {
            let expire_string = expire.to_string();
            let subject_name = cert_subject_to_string(cert, Nid::COMMONNAME);
            return Err(Error::new(
                ErrorKind::Other,
                format!("Certificate {subject_name} expired {expire_string}"),
            ));
        }
    }
    Ok(())
}

fn _verify(data_to_verify: &[u8], throw_on_expiry: bool) -> PyResult<Vec<u8>> {
    let certs = Stack::new().unwrap();
    let store = X509StoreBuilder::new().unwrap().build();

    let (pkcs7, indata) =
        Pkcs7::from_smime(data_to_verify).map_err(|err| VerifyError::new_err(err.to_string()))?;

    if throw_on_expiry {
        validate_expiry(certs.as_ref()).map_err(|err| VerifyError::new_err(err.to_string()))?;
    }

    let mut out: Vec<u8> = Vec::new();

    pkcs7
        .verify(
            certs.as_ref(),
            store.as_ref(),
            indata.as_deref(),
            Some(out.as_mut()),
            Pkcs7Flags::NOVERIFY,
        )
        .map_err(|err| VerifyError::new_err(err.to_string()))?;

    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (cert_file, key_file, data_to_sign, *, detached = false))]
fn sign(
    py: Python,
    cert_file: &str,
    key_file: &str,
    data_to_sign: Vec<u8>,
    detached: bool,
) -> PyResult<PyObject> {
    match _sign(cert_file, key_file, &data_to_sign, detached) {
        Ok(data) => Ok(PyBytes::new(py, &data).into()),
        Err(err) => Err(err),
    }
}

#[pyfunction]
#[pyo3(signature = (data_to_verify, *, throw_on_expiry = false))]
fn verify(py: Python, data_to_verify: Vec<u8>, throw_on_expiry: bool) -> PyResult<PyObject> {
    match _verify(&data_to_verify, throw_on_expiry) {
        Ok(data) => Ok(PyBytes::new(py, &data).into()),
        Err(err) => Err(err),
    }
}

#[pymodule]
fn rsmime(py: Python, m: &PyModule) -> PyResult<()> {
    m.add("CertificateError", py.get_type::<CertificateError>())?;
    m.add("SignError", py.get_type::<SignError>())?;
    m.add("VerifyError", py.get_type::<VerifyError>())?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    Ok(())
}
