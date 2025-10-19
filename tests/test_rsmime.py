from pathlib import Path

import pytest
from callee import strings

from rsmime import Rsmime, exceptions


ATTACHED_SIGNATURE_REGEX = strings.Regex(
    b'MIME-Version: 1.0\n'
    b'Content-Disposition: attachment; filename="smime.p7m"\n'
    b'Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"\n'
    b'Content-Transfer-Encoding: base64\n'
    b'\n'
    b'MIIJwQYJKoZIhvcNAQcCoIIJsjCCCa4CAQExDzANBglghkgBZQMEAgEFADASBgkq\n'
    b'[A-Za-z0-9/+=\n]+\n'
    b'\n'
)

DETACHED_SIGNATURE_REGEX = strings.Regex(
    b'MIME-Version: 1.0\n'
    b'Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; boundary="----[A-Z0-9]+"\n\n'
    b'This is an S/MIME signed message\n\n'
    b'------[A-Z0-9]+\n'
    b'abc\n'
    b'------[A-Z0-9]+\n'
    b'Content-Type: application/x-pkcs7-signature; name="smime.p7s"\n'
    b'Content-Transfer-Encoding: base64\n'
    b'Content-Disposition: attachment; filename="smime.p7s"\n'
    b'\n'
    b'MIIJugYJKoZIhvcNAQcCoIIJqzCCCacCAQExDzANBglghkgBZQMEAgEFADALBgkq\n'
    b'[A-Za-z0-9/+=\n]+\n'
    b'\n'
    b'------[A-Z0-9]+--\n'
    b'\n'
)


def _load_text(path: str) -> str:
    return Path(path).read_text()


def _load_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


working_client = Rsmime('tests/data/certificate.crt', 'tests/data/certificate.key')
expired_client = Rsmime('tests/data/expired.crt', 'tests/data/certificate.key')


class TestRsmime:
    def test_sign(self):
        signed_data = working_client.sign(b'abc')
        assert signed_data == ATTACHED_SIGNATURE_REGEX

    def test_sign_detached(self):
        signed_data = working_client.sign(b'abc', detached=True)
        assert signed_data == DETACHED_SIGNATURE_REGEX

    def test_sign_with_in_memory_material(self):
        client = Rsmime(
            cert_data=_load_text('tests/data/certificate.crt'),
            key_data=_load_text('tests/data/certificate.key'),
        )

        signed_data = client.sign(b'abc')

        assert signed_data == ATTACHED_SIGNATURE_REGEX

    def test_sign_with_in_memory_bytes_material(self):
        client = Rsmime(
            cert_data=_load_text('tests/data/certificate.crt').encode(),
            key_data=_load_text('tests/data/certificate.key').encode(),
        )

        signed_data = client.sign(b'abc')

        assert signed_data == ATTACHED_SIGNATURE_REGEX

    def test_sign_with_in_memory_bytearray_material(self):
        client = Rsmime(
            cert_data=bytearray(_load_bytes('tests/data/certificate.crt')),
            key_data=bytearray(_load_bytes('tests/data/certificate.key')),
        )

        signed_data = client.sign(b'abc')

        assert signed_data == ATTACHED_SIGNATURE_REGEX

    def test_sign_with_path_objects(self):
        client = Rsmime(
            Path('tests/data/certificate.crt'),
            Path('tests/data/certificate.key'),
        )

        signed_data = client.sign(b'abc')

        assert signed_data == ATTACHED_SIGNATURE_REGEX

    def test_sign_missing_cert(self):
        with pytest.raises(
            exceptions.CertificateError, match='No such file or directory'
        ):
            Rsmime('tests/data/missing.crt', 'tests/data/certificate.key')

    def test_sign_missing_key(self):
        with pytest.raises(
            exceptions.CertificateError, match='No such file or directory'
        ):
            Rsmime('tests/data/certificate.crt', 'tests/data/missing.key')

    def test_sign_str_error(self):
        with pytest.raises(TypeError):
            working_client.sign('abc')

    def test_sign_int_error(self):
        with pytest.raises(TypeError):
            working_client.sign(123)

    def test_sign_empty_data(self):
        with pytest.raises(exceptions.SignError, match='Cannot sign empty data'):
            working_client.sign(b'')

    def test_conflicting_certificate_inputs(self):
        with pytest.raises(
            exceptions.CertificateError,
            match='Provide either cert_file or cert_data',
        ):
            Rsmime(
                'tests/data/certificate.crt',
                'tests/data/certificate.key',
                cert_data=_load_text('tests/data/certificate.crt'),
            )

    def test_conflicting_key_inputs(self):
        with pytest.raises(
            exceptions.CertificateError,
            match='Provide either key_file or key_data',
        ):
            Rsmime(
                'tests/data/certificate.crt',
                'tests/data/certificate.key',
                key_data=_load_text('tests/data/certificate.key'),
            )

    def test_missing_certificate_input(self):
        with pytest.raises(
            exceptions.CertificateError,
            match='cert_file or cert_data',
        ):
            Rsmime(key_data=_load_text('tests/data/certificate.key'))

    def test_missing_key_input(self):
        with pytest.raises(
            exceptions.CertificateError,
            match='key_file or key_data',
        ):
            Rsmime(cert_data=_load_text('tests/data/certificate.crt'))

    def test_in_memory_material_requires_text_or_bytes(self):
        with pytest.raises(
            exceptions.CertificateError,
            match='cert_data must be a str or bytes-like object',
        ):
            Rsmime(
                cert_data=object(),
                key_data=_load_text('tests/data/certificate.key'),
            )

    def test_verify(self):
        data = b'abc'
        signed_data = working_client.sign(data)
        verified_data = Rsmime.verify(signed_data)
        assert verified_data == data

    def test_verify_expired(self):
        data = b'abc'
        signed_data = expired_client.sign(data)
        with pytest.raises(exceptions.CertificateExpiredError):
            working_client.verify(signed_data, raise_on_expired=True)
