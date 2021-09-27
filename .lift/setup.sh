#!/usr/bin/env bash
./buildconf
./configure --with-openssl
echo "Ran the setup script for Lift including autoconf and executing ./configure --with-openssl"
