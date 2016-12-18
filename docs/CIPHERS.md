# Ciphers

With curl's options `CURLOPT_SSL_CIPHER_LIST` and `--ciphers` users can
control which ciphers to consider when negotiating TLS connections.

The names of the known ciphers differ depending on which TLS backend that
libcurl was built to use. This is an attempt to list known cipher names.

## OpenSSL

(based on [OpenSSL docs](https://www.openssl.org/docs/man1.1.0/apps/ciphers.html))

### SSL3 cipher suites

`NULL-MD5`
`NULL-SHA`
`RC4-MD5`
`RC4-SHA`
`IDEA-CBC-SHA`
`DES-CBC3-SHA`
`DH-DSS-DES-CBC3-SHA`
`DH-RSA-DES-CBC3-SHA`
`DHE-DSS-DES-CBC3-SHA`
`DHE-RSA-DES-CBC3-SHA`
`ADH-RC4-MD5`
`ADH-DES-CBC3-SHA`

### TLS v1.0 cipher suites

`NULL-MD5`
`NULL-SHA`
`RC4-MD5`
`RC4-SHA`
`IDEA-CBC-SHA`
`DES-CBC3-SHA`
`DHE-DSS-DES-CBC3-SHA`
`DHE-RSA-DES-CBC3-SHA`
`ADH-RC4-MD5`
`ADH-DES-CBC3-SHA`

### AES ciphersuites from RFC3268, extending TLS v1.0

`AES128-SHA`
`AES256-SHA`
`DH-DSS-AES128-SHA`
`DH-DSS-AES256-SHA`
`DH-RSA-AES128-SHA`
`DH-RSA-AES256-SHA`
`DHE-DSS-AES128-SHA`
`DHE-DSS-AES256-SHA`
`DHE-RSA-AES128-SHA`
`DHE-RSA-AES256-SHA`
`ADH-AES128-SHA`
`ADH-AES256-SHA`

### SEED ciphersuites from RFC4162, extending TLS v1.0

`SEED-SHA`
`DH-DSS-SEED-SHA`
`DH-RSA-SEED-SHA`
`DHE-DSS-SEED-SHA`
`DHE-RSA-SEED-SHA`
`ADH-SEED-SHA`

### GOST ciphersuites, extending TLS v1.0

`GOST94-GOST89-GOST89`
`GOST2001-GOST89-GOST89`
`GOST94-NULL-GOST94`
`GOST2001-NULL-GOST94`

### Elliptic curve cipher suites

`ECDHE-RSA-NULL-SHA`
`ECDHE-RSA-RC4-SHA`
`ECDHE-RSA-DES-CBC3-SHA`
`ECDHE-RSA-AES128-SHA`
`ECDHE-RSA-AES256-SHA`
`ECDHE-ECDSA-NULL-SHA`
`ECDHE-ECDSA-RC4-SHA`
`ECDHE-ECDSA-DES-CBC3-SHA`
`ECDHE-ECDSA-AES128-SHA`
`ECDHE-ECDSA-AES256-SHA`
`AECDH-NULL-SHA`
`AECDH-RC4-SHA`
`AECDH-DES-CBC3-SHA`
`AECDH-AES128-SHA`
`AECDH-AES256-SHA`

### TLS v1.2 cipher suites

`NULL-SHA256`
`AES128-SHA256`
`AES256-SHA256`
`AES128-GCM-SHA256`
`AES256-GCM-SHA384`
`DH-RSA-AES128-SHA256`
`DH-RSA-AES256-SHA256`
`DH-RSA-AES128-GCM-SHA256`
`DH-RSA-AES256-GCM-SHA384`
`DH-DSS-AES128-SHA256`
`DH-DSS-AES256-SHA256`
`DH-DSS-AES128-GCM-SHA256`
`DH-DSS-AES256-GCM-SHA384`
`DHE-RSA-AES128-SHA256`
`DHE-RSA-AES256-SHA256`
`DHE-RSA-AES128-GCM-SHA256`
`DHE-RSA-AES256-GCM-SHA384`
`DHE-DSS-AES128-SHA256`
`DHE-DSS-AES256-SHA256`
`DHE-DSS-AES128-GCM-SHA256`
`DHE-DSS-AES256-GCM-SHA384`
`ECDHE-RSA-AES128-SHA256`
`ECDHE-RSA-AES256-SHA384`
`ECDHE-RSA-AES128-GCM-SHA256`
`ECDHE-RSA-AES256-GCM-SHA384`
`ECDHE-ECDSA-AES128-SHA256`
`ECDHE-ECDSA-AES256-SHA384`
`ECDHE-ECDSA-AES128-GCM-SHA256`
`ECDHE-ECDSA-AES256-GCM-SHA384`
`ADH-AES128-SHA256`
`ADH-AES256-SHA256`
`ADH-AES128-GCM-SHA256`
`ADH-AES256-GCM-SHA384`
`AES128-CCM`
`AES256-CCM`
`DHE-RSA-AES128-CCM`
`DHE-RSA-AES256-CCM`
`AES128-CCM8`
`AES256-CCM8`
`DHE-RSA-AES128-CCM8`
`DHE-RSA-AES256-CCM8`
`ECDHE-ECDSA-AES128-CCM`
`ECDHE-ECDSA-AES256-CCM`
`ECDHE-ECDSA-AES128-CCM8`
`ECDHE-ECDSA-AES256-CCM8`

### Camellia HMAC-Based ciphersuites from RFC6367, extending TLS v1.2

`ECDHE-ECDSA-CAMELLIA128-SHA256`
`ECDHE-ECDSA-CAMELLIA256-SHA384`
`ECDHE-RSA-CAMELLIA128-SHA256`
`ECDHE-RSA-CAMELLIA256-SHA384`

## NSS

### Totally insecure

`rc4`
`rc4-md5`
`rc4export`
`rc2`
`rc2export`
`des`
`desede3`

###  SSL3/TLS cipher suites

`rsa_rc4_128_md5`
`rsa_rc4_128_sha`
`rsa_3des_sha`
`rsa_des_sha`
`rsa_rc4_40_md5`
`rsa_rc2_40_md5`
`rsa_null_md5`
`rsa_null_sha`
`fips_3des_sha`
`fips_des_sha`
`fortezza`
`fortezza_rc4_128_sha`
`fortezza_null`

### TLS 1.0 Exportable 56-bit Cipher Suites

`rsa_des_56_sha`
`rsa_rc4_56_sha`

### AES ciphers

`dhe_dss_aes_128_cbc_sha`
`dhe_dss_aes_256_cbc_sha`
`dhe_rsa_aes_128_cbc_sha`
`dhe_rsa_aes_256_cbc_sha`
`rsa_aes_128_sha`
`rsa_aes_256_sha`

### ECC ciphers

`ecdh_ecdsa_null_sha`
`ecdh_ecdsa_rc4_128_sha`
`ecdh_ecdsa_3des_sha`
`ecdh_ecdsa_aes_128_sha`
`ecdh_ecdsa_aes_256_sha`
`ecdhe_ecdsa_null_sha`
`ecdhe_ecdsa_rc4_128_sha`
`ecdhe_ecdsa_3des_sha`
`ecdhe_ecdsa_aes_128_sha`
`ecdhe_ecdsa_aes_256_sha`
`ecdh_rsa_null_sha`
`ecdh_rsa_128_sha`
`ecdh_rsa_3des_sha`
`ecdh_rsa_aes_128_sha`
`ecdh_rsa_aes_256_sha`
`ecdhe_rsa_null`
`ecdhe_rsa_rc4_128_sha`
`ecdhe_rsa_3des_sha`
`ecdhe_rsa_aes_128_sha`
`ecdhe_rsa_aes_256_sha`
`ecdh_anon_null_sha`
`ecdh_anon_rc4_128sha`
`ecdh_anon_3des_sha`
`ecdh_anon_aes_128_sha`
`ecdh_anon_aes_256_sha`

### HMAC-SHA256 cipher suites

`rsa_null_sha_256`
`rsa_aes_128_cbc_sha_256`
`rsa_aes_256_cbc_sha_256`
`dhe_rsa_aes_128_cbc_sha_256`
`dhe_rsa_aes_256_cbc_sha_256`
`ecdhe_ecdsa_aes_128_cbc_sha_256`
`ecdhe_rsa_aes_128_cbc_sha_256`

### AES GCM cipher suites in RFC 5288 and RFC 5289

`rsa_aes_128_gcm_sha_256`
`dhe_rsa_aes_128_gcm_sha_256`
`dhe_dss_aes_128_gcm_sha_256`
`ecdhe_ecdsa_aes_128_gcm_sha_256`
`ecdh_ecdsa_aes_128_gcm_sha_256`
`ecdhe_rsa_aes_128_gcm_sha_256`
`ecdh_rsa_aes_128_gcm_sha_256`

### cipher suites using SHA384

`rsa_aes_256_gcm_sha_384`
`dhe_rsa_aes_256_gcm_sha_384`
`dhe_dss_aes_256_gcm_sha_384`
`ecdhe_ecdsa_aes_256_sha_384`
`ecdhe_rsa_aes_256_sha_384`
`ecdhe_ecdsa_aes_256_gcm_sha_384`
`ecdhe_rsa_aes_256_gcm_sha_384`

### chacha20-poly1305 cipher suites

`ecdhe_rsa_chacha20_poly1305_sha_256`
`ecdhe_ecdsa_chacha20_poly1305_sha_256`
`dhe_rsa_chacha20_poly1305_sha_256`
