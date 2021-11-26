Long: silent
Short: s
Help: Silent mode
See-also: verbose stderr no-progress-meter
Category: important verbose
Example: -s $URL
Added: 4.0
---
Silent or quiet mode. Do not show progress meter or error messages. Makes Curl
mute. It will still output the data you ask for, potentially even to the
terminal/stdout unless you redirect it.

Use --show-error in addition to this option to disable progress meter but
still show error messages.
