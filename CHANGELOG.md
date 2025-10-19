## Unreleased

Released XXXX-XX-XX

## 0.7.0

Released 2025-10-19

* [#3](https://github.com/tiwilliam/rsmime/pull/3) - Replace black with ruff for formatting.
* [#7](https://github.com/tiwilliam/rsmime/pull/7) - Introduce ``cert_data`` and ``key_data`` options for supplying certificate material without temporary files.

## 0.6.4

Released 2023-10-30

* [#2](https://github.com/tiwilliam/rsmime/pull/2) - Fix `raise_on_expired` to properly raise `CertificateExpiredError` when the token is expired on verify.

## 0.6.3

Released 2023-10-29

* Testing build pipeline changes only. Automatic documentation version generation is now enabled.

## 0.6.2

Released 2023-10-29

* **Breaking:** Renamed `data_to_sign` and `data_to_verify` passed to `sign` and `verify` to `message`.
