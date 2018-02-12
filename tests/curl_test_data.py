#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
"""Module for extracting test data from the test data folder"""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import os
import re
import logging

log = logging.getLogger(__name__)


REPLY_DATA = re.compile("<reply>\s*<data>(.*?)</data>", re.MULTILINE | re.DOTALL)


class TestData(object):
    def __init__(self, data_folder):
        self.data_folder = data_folder

    def get_test_data(self, test_number):
        # Create the test file name
        filename = os.path.join(self.data_folder,
                                "test{0}".format(test_number))

        log.debug("Parsing file %s", filename)

        with open(filename, "rb") as f:
            contents = f.read().decode("utf-8")

        m = REPLY_DATA.search(contents)
        if not m:
            raise Exception("Couldn't find a <reply><data> section")

        # Left-strip the data so we don't get a newline before our data.
        return m.group(1).lstrip()


if __name__ == '__main__':
    td = TestData("./data")
    data = td.get_test_data(1)
    print(data)
