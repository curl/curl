#!/usr/bin/env bash
# Copyright (C) 2000 - 2022 Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
autoreconf -fi
./configure --with-openssl
echo "Ran the setup script for Lift including autoconf and executing ./configure --with-openssl"
