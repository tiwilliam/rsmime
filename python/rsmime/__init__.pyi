from os import PathLike

class Rsmime:
    def __init__(
        self,
        cert_file: str | PathLike[str] | None = ...,
        key_file: str | PathLike[str] | None = ...,
        *,
        cert_data: str | bytes | bytearray | memoryview | None = ...,
        key_data: str | bytes | bytearray | memoryview | None = ...,
    ) -> None:
        """Initialize client and load certificate material.

        Parameters:
            cert_file: Path to certificate on disk. Mutually exclusive with ``cert_data``.
            key_file: Path to private key on disk. Mutually exclusive with ``key_data``.
            cert_data: PEM-encoded certificate contents provided as a string or bytes-like
                object.
            key_data: PEM-encoded private key contents provided as a string or bytes-like
                object.

        Raises:
            exceptions.CertificateError: If there is an error loading, parsing, or when
                both a file path and in-memory value are provided for the same artifact.
        """
        ...
    def sign(self, message: bytes, *, detached: bool = False) -> bytes:
        """Sign a message and return the signed S/MIME message.

        Parameters:
            message: Message to sign.
            detached: Whether to return a detached signature. When set to `True`, the
                return value will be a multipart message with the signature in the
                plain text in the first part and the signature in the second part. When
                set to `False` the return value will be the signature without
                any additional wrapping.

        Returns:
            Signed S/MIME message.

        Raises:
            exceptions.SignError: If there is an error signing the data.

        """
        ...
    @staticmethod
    def verify(message: bytes, raise_on_expired: bool = False) -> bytes:
        """Verify a signed message and return the raw message data.

        Parameters:
            message: The signed message to verify.
            raise_on_expired: Whether to raise an exception if any certificate
                in the message has expired.

        Returns:
            Raw message data.

        Raises:
            exceptions.VerifyError: If there is an error verifying the message.
            exceptions.CertificateExpiredError: If any certificate in the message has expired.
                Raise only if `raise_on_expired` is `True`.
        """
        ...
