## Note for users with TPM (Trusted Platform Module) 2.0 with OpenSSL

In order to use Curl with a TPM 2.0, you must use external engines to use your TPM 2.0
and use this command `curl --key /path/to/key.tss --cert /path/to/cert.crt https://my-server.com/download/url`.

Replace `/path/to/key.tss` with your ssl key and `/path/to/cert.crt` with your cert key.


For more information, see [this issue](https://github.com/curl/curl/issues/16474).