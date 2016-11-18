Long: negotiate
Help: Use HTTP Negotiate (SPNEGO) authentication
Protocols: HTTP
See-also: basic ntlm anyauth proxy-negotiate
---
Enables Negotiate (SPNEGO) authentication.

This option requires a library built with GSS-API or SSPI support. Use
--version to see if your curl supports GSS-API/SSPI or SPNEGO.

When using this option, you must also provide a fake --user option to activate
the authentication code properly. Sending a '-u :' is enough as the user name
and password from the --user option aren't actually used.

If this option is used several times, only the first one is used.
