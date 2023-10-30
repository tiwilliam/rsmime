## 0.6.4

Released 2023-10-30

* [#2](https://github.com/tiwilliam/rsmime/pull/2) - Fix `raise_on_expired` to properly raise `CertificateExpiredError` when the token is expired on verify.

## 0.6.3

Released 2023-10-29

* Testing build pipeline changes only. Automatic documentation version generation is now enabled.

## 0.6.2

Released 2023-10-29

* **Breaking:** Renamed `data_to_sign` and `data_to_verify` passed to `sign` and `verify` to `message`.
