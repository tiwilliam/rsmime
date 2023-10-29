import pytest
from callee import strings
from rsmime import Rsmime, exceptions

working_client = Rsmime('tests/data/certificate.crt', 'tests/data/certificate.key')
expired_client = Rsmime('tests/data/expired.crt', 'tests/data/certificate.key')

class TestRsmime:
    def test_rsmime_sign(self):
        signed_data = working_client.sign(b'abc')
        assert signed_data == strings.Regex(
            b'MIME-Version: 1.0\n'
            b'Content-Disposition: attachment; filename="smime.p7m"\n'
            b'Content-Type: application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"\n'
            b'Content-Transfer-Encoding: base64\n'
            b'\n'
            b'MIIJwQYJKoZIhvcNAQcCoIIJsjCCCa4CAQExDzANBglghkgBZQMEAgEFADASBgkq\n'
            b'[A-Za-z0-9/+=\n]+\n'
            b'\n'
        )

    def test_rsmime_sign_detached(self):
        signed_data = working_client.sign(b'abc', detached=True)
        assert signed_data == strings.Regex(
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

    def test_rsmime_sign_missing_cert(self):
        with pytest.raises(exceptions.CertificateError):
            Rsmime('tests/data/missing.crt', 'tests/data/certificate.key')

    def test_rsmime_sign_missing_key(self):
        with pytest.raises(exceptions.CertificateError):
            Rsmime('tests/data/certificate.crt', 'tests/data/missing.key')

    def test_rsmime_sign_str_error(self):
        with pytest.raises(TypeError):
            working_client.sign('abc')

    def test_rsmime_sign_int_error(self):
        with pytest.raises(TypeError):
            working_client.sign(123)

    def test_rsmime_verify(self):
        data = b'abc'
        signed_data = working_client.sign(data)
        verified_data = working_client.verify(signed_data)
        assert verified_data == data

    def test_rsmime_verify_expired(self):
        data = b'abc'
        signed_data = expired_client.sign(data)
        with pytest.raises(exceptions.CertificateExpiredError):
            working_client.verify(signed_data, raise_on_expired=True)
