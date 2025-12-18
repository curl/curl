<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# TLS 1.2 cipher suites

| Id     | IANA name                                     | OpenSSL name                       | RFC                |
|--------|-----------------------------------------------|------------------------------------|--------------------|
| 0x0001 | TLS_RSA_WITH_NULL_MD5                         | NULL-MD5                           | [RFC5246]          |
| 0x0002 | TLS_RSA_WITH_NULL_SHA                         | NULL-SHA                           | [RFC5246]          |
| 0x0003 | TLS_RSA_EXPORT_WITH_RC4_40_MD5                | EXP-RC4-MD5                        | [RFC4346][RFC6347] |
| 0x0004 | TLS_RSA_WITH_RC4_128_MD5                      | RC4-MD5                            | [RFC5246][RFC6347] |
| 0x0005 | TLS_RSA_WITH_RC4_128_SHA                      | RC4-SHA                            | [RFC5246][RFC6347] |
| 0x0006 | TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5            | EXP-RC2-CBC-MD5                    | [RFC4346]          |
| 0x0007 | TLS_RSA_WITH_IDEA_CBC_SHA                     | IDEA-CBC-SHA                       | [RFC8996]          |
| 0x0008 | TLS_RSA_EXPORT_WITH_DES40_CBC_SHA             | EXP-DES-CBC-SHA                    | [RFC4346]          |
| 0x0009 | TLS_RSA_WITH_DES_CBC_SHA                      | DES-CBC-SHA                        | [RFC8996]          |
| 0x000A | TLS_RSA_WITH_3DES_EDE_CBC_SHA                 | DES-CBC3-SHA                       | [RFC5246]          |
| 0x000B | TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA          | EXP-DH-DSS-DES-CBC-SHA             | [RFC4346]          |
| 0x000C | TLS_DH_DSS_WITH_DES_CBC_SHA                   | DH-DSS-DES-CBC-SHA                 | [RFC8996]          |
| 0x000D | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA              | DH-DSS-DES-CBC3-SHA                | [RFC5246]          |
| 0x000E | TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA          | EXP-DH-RSA-DES-CBC-SHA             | [RFC4346]          |
| 0x000F | TLS_DH_RSA_WITH_DES_CBC_SHA                   | DH-RSA-DES-CBC-SHA                 | [RFC8996]          |
| 0x0010 | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA              | DH-RSA-DES-CBC3-SHA                | [RFC5246]          |
| 0x0011 | TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA         | EXP-DHE-DSS-DES-CBC-SHA            | [RFC4346]          |
| 0x0012 | TLS_DHE_DSS_WITH_DES_CBC_SHA                  | DHE-DSS-DES-CBC-SHA                | [RFC8996]          |
| 0x0013 | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA             | DHE-DSS-DES-CBC3-SHA               | [RFC5246]          |
| 0x0014 | TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA         | EXP-DHE-RSA-DES-CBC-SHA            | [RFC4346]          |
| 0x0015 | TLS_DHE_RSA_WITH_DES_CBC_SHA                  | DHE-RSA-DES-CBC-SHA                | [RFC8996]          |
| 0x0016 | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA             | DHE-RSA-DES-CBC3-SHA               | [RFC5246]          |
| 0x0017 | TLS_DH_anon_EXPORT_WITH_RC4_40_MD5            | EXP-ADH-RC4-MD5                    | [RFC4346][RFC6347] |
| 0x0018 | TLS_DH_anon_WITH_RC4_128_MD5                  | ADH-RC4-MD5                        | [RFC5246][RFC6347] |
| 0x0019 | TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA         | EXP-ADH-DES-CBC-SHA                | [RFC4346]          |
| 0x001A | TLS_DH_anon_WITH_DES_CBC_SHA                  | ADH-DES-CBC-SHA                    | [RFC8996]          |
| 0x001B | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA             | ADH-DES-CBC3-SHA                   | [RFC5246]          |
| 0x001C |                                               | FZA-NULL-SHA                       |                    |
| 0x001D |                                               | FZA-FZA-CBC-SHA                    |                    |
| 0x001E | TLS_KRB5_WITH_DES_CBC_SHA                     | KRB5-DES-CBC-SHA                   | [RFC2712]          |
| 0x001F | TLS_KRB5_WITH_3DES_EDE_CBC_SHA                | KRB5-DES-CBC3-SHA                  | [RFC2712]          |
| 0x0020 | TLS_KRB5_WITH_RC4_128_SHA                     | KRB5-RC4-SHA                       | [RFC2712][RFC6347] |
| 0x0021 | TLS_KRB5_WITH_IDEA_CBC_SHA                    | KRB5-IDEA-CBC-SHA                  | [RFC2712]          |
| 0x0022 | TLS_KRB5_WITH_DES_CBC_MD5                     | KRB5-DES-CBC-MD5                   | [RFC2712]          |
| 0x0023 | TLS_KRB5_WITH_3DES_EDE_CBC_MD5                | KRB5-DES-CBC3-MD5                  | [RFC2712]          |
| 0x0024 | TLS_KRB5_WITH_RC4_128_MD5                     | KRB5-RC4-MD5                       | [RFC2712][RFC6347] |
| 0x0025 | TLS_KRB5_WITH_IDEA_CBC_MD5                    | KRB5-IDEA-CBC-MD5                  | [RFC2712]          |
| 0x0026 | TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA           | EXP-KRB5-DES-CBC-SHA               | [RFC2712]          |
| 0x0027 | TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA           | EXP-KRB5-RC2-CBC-SHA               | [RFC2712]          |
| 0x0028 | TLS_KRB5_EXPORT_WITH_RC4_40_SHA               | EXP-KRB5-RC4-SHA                   | [RFC2712][RFC6347] |
| 0x0029 | TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5           | EXP-KRB5-DES-CBC-MD5               | [RFC2712]          |
| 0x002A | TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5           | EXP-KRB5-RC2-CBC-MD5               | [RFC2712]          |
| 0x002B | TLS_KRB5_EXPORT_WITH_RC4_40_MD5               | EXP-KRB5-RC4-MD5                   | [RFC2712][RFC6347] |
| 0x002C | TLS_PSK_WITH_NULL_SHA                         | PSK-NULL-SHA                       | [RFC4785]          |
| 0x002D | TLS_DHE_PSK_WITH_NULL_SHA                     | DHE-PSK-NULL-SHA                   | [RFC4785]          |
| 0x002E | TLS_RSA_PSK_WITH_NULL_SHA                     | RSA-PSK-NULL-SHA                   | [RFC4785]          |
| 0x002F | TLS_RSA_WITH_AES_128_CBC_SHA                  | AES128-SHA                         | [RFC5246]          |
| 0x0030 | TLS_DH_DSS_WITH_AES_128_CBC_SHA               | DH-DSS-AES128-SHA                  | [RFC5246]          |
| 0x0031 | TLS_DH_RSA_WITH_AES_128_CBC_SHA               | DH-RSA-AES128-SHA                  | [RFC5246]          |
| 0x0032 | TLS_DHE_DSS_WITH_AES_128_CBC_SHA              | DHE-DSS-AES128-SHA                 | [RFC5246]          |
| 0x0033 | TLS_DHE_RSA_WITH_AES_128_CBC_SHA              | DHE-RSA-AES128-SHA                 | [RFC5246]          |
| 0x0034 | TLS_DH_anon_WITH_AES_128_CBC_SHA              | ADH-AES128-SHA                     | [RFC5246]          |
| 0x0035 | TLS_RSA_WITH_AES_256_CBC_SHA                  | AES256-SHA                         | [RFC5246]          |
| 0x0036 | TLS_DH_DSS_WITH_AES_256_CBC_SHA               | DH-DSS-AES256-SHA                  | [RFC5246]          |
| 0x0037 | TLS_DH_RSA_WITH_AES_256_CBC_SHA               | DH-RSA-AES256-SHA                  | [RFC5246]          |
| 0x0038 | TLS_DHE_DSS_WITH_AES_256_CBC_SHA              | DHE-DSS-AES256-SHA                 | [RFC5246]          |
| 0x0039 | TLS_DHE_RSA_WITH_AES_256_CBC_SHA              | DHE-RSA-AES256-SHA                 | [RFC5246]          |
| 0x003A | TLS_DH_anon_WITH_AES_256_CBC_SHA              | ADH-AES256-SHA                     | [RFC5246]          |
| 0x003B | TLS_RSA_WITH_NULL_SHA256                      | NULL-SHA256                        | [RFC5246]          |
| 0x003C | TLS_RSA_WITH_AES_128_CBC_SHA256               | AES128-SHA256                      | [RFC5246]          |
| 0x003D | TLS_RSA_WITH_AES_256_CBC_SHA256               | AES256-SHA256                      | [RFC5246]          |
| 0x003E | TLS_DH_DSS_WITH_AES_128_CBC_SHA256            | DH-DSS-AES128-SHA256               | [RFC5246]          |
| 0x003F | TLS_DH_RSA_WITH_AES_128_CBC_SHA256            | DH-RSA-AES128-SHA256               | [RFC5246]          |
| 0x0040 | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256           | DHE-DSS-AES128-SHA256              | [RFC5246]          |
| 0x0041 | TLS_RSA_WITH_CAMELLIA_128_CBC_SHA             | CAMELLIA128-SHA                    | [RFC5932]          |
| 0x0042 | TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA          | DH-DSS-CAMELLIA128-SHA             | [RFC5932]          |
| 0x0043 | TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA          | DH-RSA-CAMELLIA128-SHA             | [RFC5932]          |
| 0x0044 | TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA         | DHE-DSS-CAMELLIA128-SHA            | [RFC5932]          |
| 0x0045 | TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA         | DHE-RSA-CAMELLIA128-SHA            | [RFC5932]          |
| 0x0046 | TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA         | ADH-CAMELLIA128-SHA                | [RFC5932]          |
| 0x0060 |                                               | EXP1024-RC4-MD5                    |                    |
| 0x0061 |                                               | EXP1024-RC2-CBC-MD5                |                    |
| 0x0062 |                                               | EXP1024-DES-CBC-SHA                |                    |
| 0x0063 |                                               | EXP1024-DHE-DSS-DES-CBC-SHA        |                    |
| 0x0064 |                                               | EXP1024-RC4-SHA                    |                    |
| 0x0065 |                                               | EXP1024-DHE-DSS-RC4-SHA            |                    |
| 0x0066 |                                               | DHE-DSS-RC4-SHA                    |                    |
| 0x0067 | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256           | DHE-RSA-AES128-SHA256              | [RFC5246]          |
| 0x0068 | TLS_DH_DSS_WITH_AES_256_CBC_SHA256            | DH-DSS-AES256-SHA256               | [RFC5246]          |
| 0x0069 | TLS_DH_RSA_WITH_AES_256_CBC_SHA256            | DH-RSA-AES256-SHA256               | [RFC5246]          |
| 0x006A | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256           | DHE-DSS-AES256-SHA256              | [RFC5246]          |
| 0x006B | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256           | DHE-RSA-AES256-SHA256              | [RFC5246]          |
| 0x006C | TLS_DH_anon_WITH_AES_128_CBC_SHA256           | ADH-AES128-SHA256                  | [RFC5246]          |
| 0x006D | TLS_DH_anon_WITH_AES_256_CBC_SHA256           | ADH-AES256-SHA256                  | [RFC5246]          |
| 0x0080 |                                               | GOST94-GOST89-GOST89               |                    |
| 0x0081 |                                               | GOST2001-GOST89-GOST89             |                    |
| 0x0082 |                                               | GOST94-NULL-GOST94                 |                    |
| 0x0083 |                                               | GOST2001-NULL-GOST94               |                    |
| 0x0084 | TLS_RSA_WITH_CAMELLIA_256_CBC_SHA             | CAMELLIA256-SHA                    | [RFC5932]          |
| 0x0085 | TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA          | DH-DSS-CAMELLIA256-SHA             | [RFC5932]          |
| 0x0086 | TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA          | DH-RSA-CAMELLIA256-SHA             | [RFC5932]          |
| 0x0087 | TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA         | DHE-DSS-CAMELLIA256-SHA            | [RFC5932]          |
| 0x0088 | TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA         | DHE-RSA-CAMELLIA256-SHA            | [RFC5932]          |
| 0x0089 | TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA         | ADH-CAMELLIA256-SHA                | [RFC5932]          |
| 0x008A | TLS_PSK_WITH_RC4_128_SHA                      | PSK-RC4-SHA                        | [RFC4279][RFC6347] |
| 0x008B | TLS_PSK_WITH_3DES_EDE_CBC_SHA                 | PSK-3DES-EDE-CBC-SHA               | [RFC4279]          |
| 0x008C | TLS_PSK_WITH_AES_128_CBC_SHA                  | PSK-AES128-CBC-SHA                 | [RFC4279]          |
| 0x008D | TLS_PSK_WITH_AES_256_CBC_SHA                  | PSK-AES256-CBC-SHA                 | [RFC4279]          |
| 0x008E | TLS_DHE_PSK_WITH_RC4_128_SHA                  | DHE-PSK-RC4-SHA                    | [RFC4279][RFC6347] |
| 0x008F | TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA             | DHE-PSK-3DES-EDE-CBC-SHA           | [RFC4279]          |
| 0x0090 | TLS_DHE_PSK_WITH_AES_128_CBC_SHA              | DHE-PSK-AES128-CBC-SHA             | [RFC4279]          |
| 0x0091 | TLS_DHE_PSK_WITH_AES_256_CBC_SHA              | DHE-PSK-AES256-CBC-SHA             | [RFC4279]          |
| 0x0092 | TLS_RSA_PSK_WITH_RC4_128_SHA                  | RSA-PSK-RC4-SHA                    | [RFC4279][RFC6347] |
| 0x0093 | TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA             | RSA-PSK-3DES-EDE-CBC-SHA           | [RFC4279]          |
| 0x0094 | TLS_RSA_PSK_WITH_AES_128_CBC_SHA              | RSA-PSK-AES128-CBC-SHA             | [RFC4279]          |
| 0x0095 | TLS_RSA_PSK_WITH_AES_256_CBC_SHA              | RSA-PSK-AES256-CBC-SHA             | [RFC4279]          |
| 0x0096 | TLS_RSA_WITH_SEED_CBC_SHA                     | SEED-SHA                           | [RFC4162]          |
| 0x0097 | TLS_DH_DSS_WITH_SEED_CBC_SHA                  | DH-DSS-SEED-SHA                    | [RFC4162]          |
| 0x0098 | TLS_DH_RSA_WITH_SEED_CBC_SHA                  | DH-RSA-SEED-SHA                    | [RFC4162]          |
| 0x0099 | TLS_DHE_DSS_WITH_SEED_CBC_SHA                 | DHE-DSS-SEED-SHA                   | [RFC4162]          |
| 0x009A | TLS_DHE_RSA_WITH_SEED_CBC_SHA                 | DHE-RSA-SEED-SHA                   | [RFC4162]          |
| 0x009B | TLS_DH_anon_WITH_SEED_CBC_SHA                 | ADH-SEED-SHA                       | [RFC4162]          |
| 0x009C | TLS_RSA_WITH_AES_128_GCM_SHA256               | AES128-GCM-SHA256                  | [RFC5288]          |
| 0x009D | TLS_RSA_WITH_AES_256_GCM_SHA384               | AES256-GCM-SHA384                  | [RFC5288]          |
| 0x009E | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           | DHE-RSA-AES128-GCM-SHA256          | [RFC5288]          |
| 0x009F | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           | DHE-RSA-AES256-GCM-SHA384          | [RFC5288]          |
| 0x00A0 | TLS_DH_RSA_WITH_AES_128_GCM_SHA256            | DH-RSA-AES128-GCM-SHA256           | [RFC5288]          |
| 0x00A1 | TLS_DH_RSA_WITH_AES_256_GCM_SHA384            | DH-RSA-AES256-GCM-SHA384           | [RFC5288]          |
| 0x00A2 | TLS_DHE_DSS_WITH_AES_128_GCM_SHA256           | DHE-DSS-AES128-GCM-SHA256          | [RFC5288]          |
| 0x00A3 | TLS_DHE_DSS_WITH_AES_256_GCM_SHA384           | DHE-DSS-AES256-GCM-SHA384          | [RFC5288]          |
| 0x00A4 | TLS_DH_DSS_WITH_AES_128_GCM_SHA256            | DH-DSS-AES128-GCM-SHA256           | [RFC5288]          |
| 0x00A5 | TLS_DH_DSS_WITH_AES_256_GCM_SHA384            | DH-DSS-AES256-GCM-SHA384           | [RFC5288]          |
| 0x00A6 | TLS_DH_anon_WITH_AES_128_GCM_SHA256           | ADH-AES128-GCM-SHA256              | [RFC5288]          |
| 0x00A7 | TLS_DH_anon_WITH_AES_256_GCM_SHA384           | ADH-AES256-GCM-SHA384              | [RFC5288]          |
| 0x00A8 | TLS_PSK_WITH_AES_128_GCM_SHA256               | PSK-AES128-GCM-SHA256              | [RFC5487]          |
| 0x00A9 | TLS_PSK_WITH_AES_256_GCM_SHA384               | PSK-AES256-GCM-SHA384              | [RFC5487]          |
| 0x00AA | TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           | DHE-PSK-AES128-GCM-SHA256          | [RFC5487]          |
| 0x00AB | TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           | DHE-PSK-AES256-GCM-SHA384          | [RFC5487]          |
| 0x00AC | TLS_RSA_PSK_WITH_AES_128_GCM_SHA256           | RSA-PSK-AES128-GCM-SHA256          | [RFC5487]          |
| 0x00AD | TLS_RSA_PSK_WITH_AES_256_GCM_SHA384           | RSA-PSK-AES256-GCM-SHA384          | [RFC5487]          |
| 0x00AE | TLS_PSK_WITH_AES_128_CBC_SHA256               | PSK-AES128-CBC-SHA256              | [RFC5487]          |
| 0x00AF | TLS_PSK_WITH_AES_256_CBC_SHA384               | PSK-AES256-CBC-SHA384              | [RFC5487]          |
| 0x00B0 | TLS_PSK_WITH_NULL_SHA256                      | PSK-NULL-SHA256                    | [RFC5487]          |
| 0x00B1 | TLS_PSK_WITH_NULL_SHA384                      | PSK-NULL-SHA384                    | [RFC5487]          |
| 0x00B2 | TLS_DHE_PSK_WITH_AES_128_CBC_SHA256           | DHE-PSK-AES128-CBC-SHA256          | [RFC5487]          |
| 0x00B3 | TLS_DHE_PSK_WITH_AES_256_CBC_SHA384           | DHE-PSK-AES256-CBC-SHA384          | [RFC5487]          |
| 0x00B4 | TLS_DHE_PSK_WITH_NULL_SHA256                  | DHE-PSK-NULL-SHA256                | [RFC5487]          |
| 0x00B5 | TLS_DHE_PSK_WITH_NULL_SHA384                  | DHE-PSK-NULL-SHA384                | [RFC5487]          |
| 0x00B6 | TLS_RSA_PSK_WITH_AES_128_CBC_SHA256           | RSA-PSK-AES128-CBC-SHA256          | [RFC5487]          |
| 0x00B7 | TLS_RSA_PSK_WITH_AES_256_CBC_SHA384           | RSA-PSK-AES256-CBC-SHA384          | [RFC5487]          |
| 0x00B8 | TLS_RSA_PSK_WITH_NULL_SHA256                  | RSA-PSK-NULL-SHA256                | [RFC5487]          |
| 0x00B9 | TLS_RSA_PSK_WITH_NULL_SHA384                  | RSA-PSK-NULL-SHA384                | [RFC5487]          |
| 0x00BA | TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256          | CAMELLIA128-SHA256                 | [RFC5932]          |
| 0x00BD | TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256      | DHE-DSS-CAMELLIA128-SHA256         | [RFC5932]          |
| 0x00BE | TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      | DHE-RSA-CAMELLIA128-SHA256         | [RFC5932]          |
| 0x00BF | TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256      | ADH-CAMELLIA128-SHA256             | [RFC5932]          |
| 0x00C0 | TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256          | CAMELLIA256-SHA256                 | [RFC5932]          |
| 0x00C3 | TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256      | DHE-DSS-CAMELLIA256-SHA256         | [RFC5932]          |
| 0x00C4 | TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256      | DHE-RSA-CAMELLIA256-SHA256         | [RFC5932]          |
| 0x00C5 | TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256      | ADH-CAMELLIA256-SHA256             | [RFC5932]          |
| 0x00FF | TLS_EMPTY_RENEGOTIATION_INFO_SCSV             |                                    | [RFC5746]          |
| 0x5600 | TLS_FALLBACK_SCSV                             |                                    | [RFC7507]          |
| 0xC001 | TLS_ECDH_ECDSA_WITH_NULL_SHA                  | ECDH-ECDSA-NULL-SHA                | [RFC8422]          |
| 0xC002 | TLS_ECDH_ECDSA_WITH_RC4_128_SHA               | ECDH-ECDSA-RC4-SHA                 | [RFC8422][RFC6347] |
| 0xC003 | TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA          | ECDH-ECDSA-DES-CBC3-SHA            | [RFC8422]          |
| 0xC004 | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA           | ECDH-ECDSA-AES128-SHA              | [RFC8422]          |
| 0xC005 | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA           | ECDH-ECDSA-AES256-SHA              | [RFC8422]          |
| 0xC006 | TLS_ECDHE_ECDSA_WITH_NULL_SHA                 | ECDHE-ECDSA-NULL-SHA               | [RFC8422]          |
| 0xC007 | TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              | ECDHE-ECDSA-RC4-SHA                | [RFC8422][RFC6347] |
| 0xC008 | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA         | ECDHE-ECDSA-DES-CBC3-SHA           | [RFC8422]          |
| 0xC009 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          | ECDHE-ECDSA-AES128-SHA             | [RFC8422]          |
| 0xC00A | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          | ECDHE-ECDSA-AES256-SHA             | [RFC8422]          |
| 0xC00B | TLS_ECDH_RSA_WITH_NULL_SHA                    | ECDH-RSA-NULL-SHA                  | [RFC8422]          |
| 0xC00C | TLS_ECDH_RSA_WITH_RC4_128_SHA                 | ECDH-RSA-RC4-SHA                   | [RFC8422][RFC6347] |
| 0xC00D | TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA            | ECDH-RSA-DES-CBC3-SHA              | [RFC8422]          |
| 0xC00E | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA             | ECDH-RSA-AES128-SHA                | [RFC8422]          |
| 0xC00F | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA             | ECDH-RSA-AES256-SHA                | [RFC8422]          |
| 0xC010 | TLS_ECDHE_RSA_WITH_NULL_SHA                   | ECDHE-RSA-NULL-SHA                 | [RFC8422]          |
| 0xC011 | TLS_ECDHE_RSA_WITH_RC4_128_SHA                | ECDHE-RSA-RC4-SHA                  | [RFC8422][RFC6347] |
| 0xC012 | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           | ECDHE-RSA-DES-CBC3-SHA             | [RFC8422]          |
| 0xC013 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            | ECDHE-RSA-AES128-SHA               | [RFC8422]          |
| 0xC014 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            | ECDHE-RSA-AES256-SHA               | [RFC8422]          |
| 0xC015 | TLS_ECDH_anon_WITH_NULL_SHA                   | AECDH-NULL-SHA                     | [RFC8422]          |
| 0xC016 | TLS_ECDH_anon_WITH_RC4_128_SHA                | AECDH-RC4-SHA                      | [RFC8422][RFC6347] |
| 0xC017 | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA           | AECDH-DES-CBC3-SHA                 | [RFC8422]          |
| 0xC018 | TLS_ECDH_anon_WITH_AES_128_CBC_SHA            | AECDH-AES128-SHA                   | [RFC8422]          |
| 0xC019 | TLS_ECDH_anon_WITH_AES_256_CBC_SHA            | AECDH-AES256-SHA                   | [RFC8422]          |
| 0xC01A | TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA             | SRP-3DES-EDE-CBC-SHA               | [RFC5054]          |
| 0xC01B | TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         | SRP-RSA-3DES-EDE-CBC-SHA           | [RFC5054]          |
| 0xC01C | TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         | SRP-DSS-3DES-EDE-CBC-SHA           | [RFC5054]          |
| 0xC01D | TLS_SRP_SHA_WITH_AES_128_CBC_SHA              | SRP-AES-128-CBC-SHA                | [RFC5054]          |
| 0xC01E | TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA          | SRP-RSA-AES-128-CBC-SHA            | [RFC5054]          |
| 0xC01F | TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA          | SRP-DSS-AES-128-CBC-SHA            | [RFC5054]          |
| 0xC020 | TLS_SRP_SHA_WITH_AES_256_CBC_SHA              | SRP-AES-256-CBC-SHA                | [RFC5054]          |
| 0xC021 | TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA          | SRP-RSA-AES-256-CBC-SHA            | [RFC5054]          |
| 0xC022 | TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA          | SRP-DSS-AES-256-CBC-SHA            | [RFC5054]          |
| 0xC023 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       | ECDHE-ECDSA-AES128-SHA256          | [RFC5289]          |
| 0xC024 | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       | ECDHE-ECDSA-AES256-SHA384          | [RFC5289]          |
| 0xC025 | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256        | ECDH-ECDSA-AES128-SHA256           | [RFC5289]          |
| 0xC026 | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384        | ECDH-ECDSA-AES256-SHA384           | [RFC5289]          |
| 0xC027 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         | ECDHE-RSA-AES128-SHA256            | [RFC5289]          |
| 0xC028 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         | ECDHE-RSA-AES256-SHA384            | [RFC5289]          |
| 0xC029 | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256          | ECDH-RSA-AES128-SHA256             | [RFC5289]          |
| 0xC02A | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384          | ECDH-RSA-AES256-SHA384             | [RFC5289]          |
| 0xC02B | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | ECDHE-ECDSA-AES128-GCM-SHA256      | [RFC5289]          |
| 0xC02C | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | ECDHE-ECDSA-AES256-GCM-SHA384      | [RFC5289]          |
| 0xC02D | TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256        | ECDH-ECDSA-AES128-GCM-SHA256       | [RFC5289]          |
| 0xC02E | TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384        | ECDH-ECDSA-AES256-GCM-SHA384       | [RFC5289]          |
| 0xC02F | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | ECDHE-RSA-AES128-GCM-SHA256        | [RFC5289]          |
| 0xC030 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | ECDHE-RSA-AES256-GCM-SHA384        | [RFC5289]          |
| 0xC031 | TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256          | ECDH-RSA-AES128-GCM-SHA256         | [RFC5289]          |
| 0xC032 | TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384          | ECDH-RSA-AES256-GCM-SHA384         | [RFC5289]          |
| 0xC033 | TLS_ECDHE_PSK_WITH_RC4_128_SHA                | ECDHE-PSK-RC4-SHA                  | [RFC5489][RFC6347] |
| 0xC034 | TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA           | ECDHE-PSK-3DES-EDE-CBC-SHA         | [RFC5489]          |
| 0xC035 | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA            | ECDHE-PSK-AES128-CBC-SHA           | [RFC5489]          |
| 0xC036 | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA            | ECDHE-PSK-AES256-CBC-SHA           | [RFC5489]          |
| 0xC037 | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         | ECDHE-PSK-AES128-CBC-SHA256        | [RFC5489]          |
| 0xC038 | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384         | ECDHE-PSK-AES256-CBC-SHA384        | [RFC5489]          |
| 0xC039 | TLS_ECDHE_PSK_WITH_NULL_SHA                   | ECDHE-PSK-NULL-SHA                 | [RFC5489]          |
| 0xC03A | TLS_ECDHE_PSK_WITH_NULL_SHA256                | ECDHE-PSK-NULL-SHA256              | [RFC5489]          |
| 0xC03B | TLS_ECDHE_PSK_WITH_NULL_SHA384                | ECDHE-PSK-NULL-SHA384              | [RFC5489]          |
| 0xC03C | TLS_RSA_WITH_ARIA_128_CBC_SHA256              | ARIA128-SHA256                     | [RFC6209]          |
| 0xC03D | TLS_RSA_WITH_ARIA_256_CBC_SHA384              | ARIA256-SHA384                     | [RFC6209]          |
| 0xC044 | TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256          | DHE-RSA-ARIA128-SHA256             | [RFC6209]          |
| 0xC045 | TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384          | DHE-RSA-ARIA256-SHA384             | [RFC6209]          |
| 0xC048 | TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256      | ECDHE-ECDSA-ARIA128-SHA256         | [RFC6209]          |
| 0xC049 | TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384      | ECDHE-ECDSA-ARIA256-SHA384         | [RFC6209]          |
| 0xC04A | TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256       | ECDH-ECDSA-ARIA128-SHA256          | [RFC6209]          |
| 0xC04B | TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384       | ECDH-ECDSA-ARIA256-SHA384          | [RFC6209]          |
| 0xC04C | TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256        | ECDHE-ARIA128-SHA256               | [RFC6209]          |
| 0xC04D | TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384        | ECDHE-ARIA256-SHA384               | [RFC6209]          |
| 0xC04E | TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256         | ECDH-ARIA128-SHA256                | [RFC6209]          |
| 0xC04F | TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384         | ECDH-ARIA256-SHA384                | [RFC6209]          |
| 0xC050 | TLS_RSA_WITH_ARIA_128_GCM_SHA256              | ARIA128-GCM-SHA256                 | [RFC6209]          |
| 0xC051 | TLS_RSA_WITH_ARIA_256_GCM_SHA384              | ARIA256-GCM-SHA384                 | [RFC6209]          |
| 0xC052 | TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256          | DHE-RSA-ARIA128-GCM-SHA256         | [RFC6209]          |
| 0xC053 | TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384          | DHE-RSA-ARIA256-GCM-SHA384         | [RFC6209]          |
| 0xC056 | TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256          | DHE-DSS-ARIA128-GCM-SHA256         | [RFC6209]          |
| 0xC057 | TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384          | DHE-DSS-ARIA256-GCM-SHA384         | [RFC6209]          |
| 0xC05C | TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      | ECDHE-ECDSA-ARIA128-GCM-SHA256     | [RFC6209]          |
| 0xC05D | TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      | ECDHE-ECDSA-ARIA256-GCM-SHA384     | [RFC6209]          |
| 0xC05E | TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256       | ECDH-ECDSA-ARIA128-GCM-SHA256      | [RFC6209]          |
| 0xC05F | TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384       | ECDH-ECDSA-ARIA256-GCM-SHA384      | [RFC6209]          |
| 0xC060 | TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        | ECDHE-ARIA128-GCM-SHA256           | [RFC6209]          |
| 0xC061 | TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        | ECDHE-ARIA256-GCM-SHA384           | [RFC6209]          |
| 0xC062 | TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256         | ECDH-ARIA128-GCM-SHA256            | [RFC6209]          |
| 0xC063 | TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384         | ECDH-ARIA256-GCM-SHA384            | [RFC6209]          |
| 0xC064 | TLS_PSK_WITH_ARIA_128_CBC_SHA256              | PSK-ARIA128-SHA256                 | [RFC6209]          |
| 0xC065 | TLS_PSK_WITH_ARIA_256_CBC_SHA384              | PSK-ARIA256-SHA384                 | [RFC6209]          |
| 0xC066 | TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256          | DHE-PSK-ARIA128-SHA256             | [RFC6209]          |
| 0xC067 | TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384          | DHE-PSK-ARIA256-SHA384             | [RFC6209]          |
| 0xC068 | TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256          | RSA-PSK-ARIA128-SHA256             | [RFC6209]          |
| 0xC069 | TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384          | RSA-PSK-ARIA256-SHA384             | [RFC6209]          |
| 0xC06A | TLS_PSK_WITH_ARIA_128_GCM_SHA256              | PSK-ARIA128-GCM-SHA256             | [RFC6209]          |
| 0xC06B | TLS_PSK_WITH_ARIA_256_GCM_SHA384              | PSK-ARIA256-GCM-SHA384             | [RFC6209]          |
| 0xC06C | TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256          | DHE-PSK-ARIA128-GCM-SHA256         | [RFC6209]          |
| 0xC06D | TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384          | DHE-PSK-ARIA256-GCM-SHA384         | [RFC6209]          |
| 0xC06E | TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256          | RSA-PSK-ARIA128-GCM-SHA256         | [RFC6209]          |
| 0xC06F | TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384          | RSA-PSK-ARIA256-GCM-SHA384         | [RFC6209]          |
| 0xC070 | TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256        | ECDHE-PSK-ARIA128-SHA256           | [RFC6209]          |
| 0xC071 | TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384        | ECDHE-PSK-ARIA256-SHA384           | [RFC6209]          |
| 0xC072 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  | ECDHE-ECDSA-CAMELLIA128-SHA256     | [RFC6367]          |
| 0xC073 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  | ECDHE-ECDSA-CAMELLIA256-SHA384     | [RFC6367]          |
| 0xC074 | TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256   | ECDH-ECDSA-CAMELLIA128-SHA256      | [RFC6367]          |
| 0xC075 | TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384   | ECDH-ECDSA-CAMELLIA256-SHA384      | [RFC6367]          |
| 0xC076 | TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256    | ECDHE-RSA-CAMELLIA128-SHA256       | [RFC6367]          |
| 0xC077 | TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384    | ECDHE-RSA-CAMELLIA256-SHA384       | [RFC6367]          |
| 0xC078 | TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256     | ECDH-CAMELLIA128-SHA256            | [RFC6367]          |
| 0xC079 | TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384     | ECDH-CAMELLIA256-SHA384            | [RFC6367]          |
| 0xC07A | TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256          | CAMELLIA128-GCM-SHA256             | [RFC6367]          |
| 0xC07B | TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384          | CAMELLIA256-GCM-SHA384             | [RFC6367]          |
| 0xC07C | TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      | DHE-RSA-CAMELLIA128-GCM-SHA256     | [RFC6367]          |
| 0xC07D | TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      | DHE-RSA-CAMELLIA256-GCM-SHA384     | [RFC6367]          |
| 0xC086 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  | ECDHE-ECDSA-CAMELLIA128-GCM-SHA256 | [RFC6367]          |
| 0xC087 | TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  | ECDHE-ECDSA-CAMELLIA256-GCM-SHA384 | [RFC6367]          |
| 0xC088 | TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   | ECDH-ECDSA-CAMELLIA128-GCM-SHA256  | [RFC6367]          |
| 0xC089 | TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   | ECDH-ECDSA-CAMELLIA256-GCM-SHA384  | [RFC6367]          |
| 0xC08A | TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256    | ECDHE-CAMELLIA128-GCM-SHA256       | [RFC6367]          |
| 0xC08B | TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384    | ECDHE-CAMELLIA256-GCM-SHA384       | [RFC6367]          |
| 0xC08C | TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256     | ECDH-CAMELLIA128-GCM-SHA256        | [RFC6367]          |
| 0xC08D | TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384     | ECDH-CAMELLIA256-GCM-SHA384        | [RFC6367]          |
| 0xC08E | TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256          | PSK-CAMELLIA128-GCM-SHA256         | [RFC6367]          |
| 0xC08F | TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384          | PSK-CAMELLIA256-GCM-SHA384         | [RFC6367]          |
| 0xC090 | TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256      | DHE-PSK-CAMELLIA128-GCM-SHA256     | [RFC6367]          |
| 0xC091 | TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384      | DHE-PSK-CAMELLIA256-GCM-SHA384     | [RFC6367]          |
| 0xC092 | TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256      | RSA-PSK-CAMELLIA128-GCM-SHA256     | [RFC6367]          |
| 0xC093 | TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384      | RSA-PSK-CAMELLIA256-GCM-SHA384     | [RFC6367]          |
| 0xC094 | TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256          | PSK-CAMELLIA128-SHA256             | [RFC6367]          |
| 0xC095 | TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384          | PSK-CAMELLIA256-SHA384             | [RFC6367]          |
| 0xC096 | TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      | DHE-PSK-CAMELLIA128-SHA256         | [RFC6367]          |
| 0xC097 | TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      | DHE-PSK-CAMELLIA256-SHA384         | [RFC6367]          |
| 0xC098 | TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256      | RSA-PSK-CAMELLIA128-SHA256         | [RFC6367]          |
| 0xC099 | TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384      | RSA-PSK-CAMELLIA256-SHA384         | [RFC6367]          |
| 0xC09A | TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    | ECDHE-PSK-CAMELLIA128-SHA256       | [RFC6367]          |
| 0xC09B | TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    | ECDHE-PSK-CAMELLIA256-SHA384       | [RFC6367]          |
| 0xC09C | TLS_RSA_WITH_AES_128_CCM                      | AES128-CCM                         | [RFC6655]          |
| 0xC09D | TLS_RSA_WITH_AES_256_CCM                      | AES256-CCM                         | [RFC6655]          |
| 0xC09E | TLS_DHE_RSA_WITH_AES_128_CCM                  | DHE-RSA-AES128-CCM                 | [RFC6655]          |
| 0xC09F | TLS_DHE_RSA_WITH_AES_256_CCM                  | DHE-RSA-AES256-CCM                 | [RFC6655]          |
| 0xC0A0 | TLS_RSA_WITH_AES_128_CCM_8                    | AES128-CCM8                        | [RFC6655]          |
| 0xC0A1 | TLS_RSA_WITH_AES_256_CCM_8                    | AES256-CCM8                        | [RFC6655]          |
| 0xC0A2 | TLS_DHE_RSA_WITH_AES_128_CCM_8                | DHE-RSA-AES128-CCM8                | [RFC6655]          |
| 0xC0A3 | TLS_DHE_RSA_WITH_AES_256_CCM_8                | DHE-RSA-AES256-CCM8                | [RFC6655]          |
| 0xC0A4 | TLS_PSK_WITH_AES_128_CCM                      | PSK-AES128-CCM                     | [RFC6655]          |
| 0xC0A5 | TLS_PSK_WITH_AES_256_CCM                      | PSK-AES256-CCM                     | [RFC6655]          |
| 0xC0A6 | TLS_DHE_PSK_WITH_AES_128_CCM                  | DHE-PSK-AES128-CCM                 | [RFC6655]          |
| 0xC0A7 | TLS_DHE_PSK_WITH_AES_256_CCM                  | DHE-PSK-AES256-CCM                 | [RFC6655]          |
| 0xC0A8 | TLS_PSK_WITH_AES_128_CCM_8                    | PSK-AES128-CCM8                    | [RFC6655]          |
| 0xC0A9 | TLS_PSK_WITH_AES_256_CCM_8                    | PSK-AES256-CCM8                    | [RFC6655]          |
| 0xC0AA | TLS_PSK_DHE_WITH_AES_128_CCM_8                | DHE-PSK-AES128-CCM8                | [RFC6655]          |
| 0xC0AB | TLS_PSK_DHE_WITH_AES_256_CCM_8                | DHE-PSK-AES256-CCM8                | [RFC6655]          |
| 0xC0AC | TLS_ECDHE_ECDSA_WITH_AES_128_CCM              | ECDHE-ECDSA-AES128-CCM             | [RFC7251]          |
| 0xC0AD | TLS_ECDHE_ECDSA_WITH_AES_256_CCM              | ECDHE-ECDSA-AES256-CCM             | [RFC7251]          |
| 0xC0AE | TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            | ECDHE-ECDSA-AES128-CCM8            | [RFC7251]          |
| 0xC0AF | TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            | ECDHE-ECDSA-AES256-CCM8            | [RFC7251]          |
| 0xC100 | TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC  | GOST2012-KUZNYECHIK-KUZNYECHIKOMAC | [RFC9189]          |
| 0xC101 | TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC       | GOST2012-MAGMA-MAGMAOMAC           | [RFC9189]          |
| 0xC102 | TLS_GOSTR341112_256_WITH_28147_CNT_IMIT       | IANA-GOST2012-GOST8912-GOST8912    | [RFC9189]          |
| 0xCC13 |                                               | ECDHE-RSA-CHACHA20-POLY1305-OLD    |                    |
| 0xCC14 |                                               | ECDHE-ECDSA-CHACHA20-POLY1305-OLD  |                    |
| 0xCC15 |                                               | DHE-RSA-CHACHA20-POLY1305-OLD      |                    |
| 0xCCA8 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | ECDHE-RSA-CHACHA20-POLY1305        | [RFC7905]          |
| 0xCCA9 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | ECDHE-ECDSA-CHACHA20-POLY1305      | [RFC7905]          |
| 0xCCAA | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     | DHE-RSA-CHACHA20-POLY1305          | [RFC7905]          |
| 0xCCAB | TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         | PSK-CHACHA20-POLY1305              | [RFC7905]          |
| 0xCCAC | TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   | ECDHE-PSK-CHACHA20-POLY1305        | [RFC7905]          |
| 0xCCAD | TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     | DHE-PSK-CHACHA20-POLY1305          | [RFC7905]          |
| 0xCCAE | TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     | RSA-PSK-CHACHA20-POLY1305          | [RFC7905]          |
| 0xD001 | TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         | ECDHE-PSK-AES128-GCM-SHA256        | [RFC8442]          |
| 0xE011 |                                               | ECDHE-ECDSA-SM4-CBC-SM3            |                    |
| 0xE051 |                                               | ECDHE-ECDSA-SM4-GCM-SM3            |                    |
| 0xE052 |                                               | ECDHE-ECDSA-SM4-CCM-SM3            |                    |
| 0xFF00 |                                               | GOST-MD5                           |                    |
| 0xFF01 |                                               | GOST-GOST94                        |                    |
| 0xFF02 |                                               | GOST-GOST89MAC                     |                    |
| 0xFF03 |                                               | GOST-GOST89STREAM                  |                    |
