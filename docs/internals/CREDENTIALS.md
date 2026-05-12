<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl `creds`

Authorization credentials are kept in `struct Curl_creds`. This contains:

* `user`: the username, maybe the empty string
* `passwd`: the password, maybe the empty string
* `sasl_authzid`: the SASL `authz` value, maybe the empty string
* `oauth_bearer`: the OAUTH bearer token, maybe the empty string
* `source`: where the credentials from
* `refcount`: a reference counter to link/unlink `creds`

A `creds` with all values empty is equivalent to NULL, e.g. no `creds`
instance. With reference counting, `creds` can be linked in several places.

Two `creds` are the same if all values are equal apart from `source`
and `refcount`. The comparison of strings is done via `Curl_timestrcmp()`
to prevent side channel attacks.

## `creds` locations

Credentials are kept in three places:

* `data->state.creds`: the credentials to use for the transfer in talking
  to the `origin` (see PEERS)
* `conn->creds`: the credentials tied to a connection (more below)
* `conn->*_proxy.creds`: credentials used to talk to the `conn->*_proxy.peer`

### `data->state.creds`

This `creds` instance is created when the transfer starts looking for a
suitable connection. For an `easy_perform()` this may happen several times
if, for example, http redirects are followed.

When an `easy_perform()` starts, the transfer's `data->state.initial_origin`
peer is cleared. When creating the connection, `conn->origin` is calculated
(e.g. who the request talks to). If `data->state.initial_origin` is not
set, the first `conn->origin` is linked there. Now `libcurl` knows where
the transfer initially talked to on all possible subsequent requests.

Credential information from `CURLOPT_*` settings is only applicable for the
initial origin. Any followup request going to another origin must not
use it. Therefore `data->state.creds` is *only* created from `CURLOPT_*`
when current origin and initial origin match.

Without credentials from `CURLOPT_*`, the URL is inspected for user and
password and `netrc` is consulted as well (when built in).

### `conn->creds`

Once `data->state.creds` is known, the connection credentials are
determined. For protocols that tie authorization to everything send
on a connection (protocols without flag `PROTOPT_CREDSPERREQUEST`),
`conn->creds` is linked to `data->state.creds`. Only connections
carrying the same credentials may be reused.

Protocol with flag `PROTOPT_CREDSPERREQUEST` leave `conn->creds` empty,
as connections for such protocols may be reused with different
credentials.

That being said, there are authentication schemes like `NTLM` and
`NEGOTIATE` that tie credentials to a connection. Those do set `conn->creds`
once they start to operate, preventing connection reuse from then on
for transfers with different credentials.

### `conn->*_proxy.creds`

Those are set during connection setup from the `CURLOPT_*` values. They
do not require any "initial origin" handling as the origin of a proxy
does not change for a transfer.
