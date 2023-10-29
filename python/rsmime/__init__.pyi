def sign(cert_file: str, key_file: str, data_to_sign: bytes, *, detached: bool = False) -> bytes:
    """Sign a message and return the signed S/MIME message.

    Parameters:
        cert_file: Path to certificate on disk.
        key_file: Path to private key on disk.
        data_to_sign: Data to sign.
        detached: Whether to return a detached signature. When set to `True`, the
            return value will be a multipart message with the signature in the
            plain text in the first part and the signature in the second part. When
            set to `False` the return value will be the signature without
            any additional wrapping.

    Returns:
        Signed S/MIME message.

    Raises:
        CertificateError: If there is an error with the input certificate.
        SignError: If there is an error signing the data.
        
    """
    ...

def verify(data_to_verify: bytes, throw_on_expired: bool = False) -> bytes:
    """Verify a signed message and return the raw message data.

    Parameters:
        data_to_verify: The signed message to verify.
        throw_on_expired: Whether to throw an exception if any
            certificate in the message has expired.
    
    Returns:
        Raw message data.

    Raises:
        VerifyError: If there is an error verifying the message.
        CertificateExpiredError: If any certificate in the message has expired. Thrown only
            if `throw_on_expired` is `True`.
    """
    ...
