<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# PROGRESS METER

curl normally displays a progress meter during operations, indicating the
amount of transferred data, transfer speeds and estimated time left, etc. The
progress meter displays the transfer rate in bytes per second. The suffixes
(k, M, G, T, P) are 1024 based. For example 1k is 1024 bytes. 1M is 1048576
bytes.

curl displays this data to the terminal by default, so if you invoke curl to
do an operation and it is about to write data to the terminal, it *disables*
the progress meter as otherwise it would mess up the output mixing progress
meter and response data.

If you want a progress meter for HTTP POST or PUT requests, you need to
redirect the response output to a file, using shell redirect (\>), --output
or similar.

This does not apply to FTP upload as that operation does not spit out any
response data to the terminal.

If you prefer a progress bar instead of the regular meter, --progress-bar is
your friend. You can also disable the progress meter completely with the
--silent option.
