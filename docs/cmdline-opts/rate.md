---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: rate
Arg: <max request rate>
Help: Request rate for serial transfers
Category: connection global
Added: 7.84.0
Multi: single
Scope: global
See-also:
  - limit-rate
  - retry-delay
Example:
  - --rate 2/s $URL ...
  - --rate 3/h $URL ...
  - --rate 14/m $URL ...
---

# `--rate`

Specify the maximum transfer frequency you allow curl to use - in number of
transfer starts per time unit (sometimes called request rate). Without this
option, curl starts the next transfer as fast as possible.

If given several URLs and a transfer completes faster than the allowed rate,
curl waits until the next transfer is started to maintain the requested
rate. This option has no effect when --parallel is used.

The request rate is provided as "N/U" where N is an integer number and U is a
time unit. Supported units are 's' (second), 'm' (minute), 'h' (hour) and 'd'
/(day, as in a 24 hour unit). The default time unit, if no "/U" is provided,
is number of transfers per hour.

If curl is told to allow 10 requests per minute, it does not start the next
request until 6 seconds have elapsed since the previous transfer was started.

This function uses millisecond resolution. If the allowed frequency is set
more than 1000 per second, it instead runs unrestricted.

When retrying transfers, enabled with --retry, the separate retry delay logic
is used and not this setting.

Starting in version 8.10.0, you can specify the number of time units in the rate
expression. Make curl do no more than 5 transfers per 15 seconds with "5/15s"
or limit it to 3 transfers per 4 hours with "3/4h". No spaces allowed.
