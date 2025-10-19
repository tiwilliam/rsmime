from os import PathLike

class Rsmime:
    def __init__(
        self,
        cert_file: str | PathLike[str] | None = ...,
        key_file: str | PathLike[str] | None = ...,
        *,
        cert_data: str | bytes | bytearray | memoryview | None = ...,
        key_data: str | bytes | bytearray | memoryview | None = ...,
    ) -> None: ...

    def sign(self, message: bytes, *, detached: bool = False) -> bytes: ...

    @staticmethod
    def verify(message: bytes, raise_on_expired: bool = False) -> bytes: ...
