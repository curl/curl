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
import xml.etree.ElementTree as ET
import logging

log = logging.getLogger(__name__)


class TestData(object):
    def __init__(self, data_folder):
        self.data_folder = data_folder

    def get_test_data(self, test_number):
        # Create the test file name
        filename = os.path.join(self.data_folder,
                                "test{0}".format(test_number))

        # The user should handle the exception from failing to find the file.
        tree = ET.parse(filename)

        # We need the <reply><data> text.
        reply = tree.find("reply")
        data = reply.find("data")

        # Return the text contents of the data
        return data.text


if __name__ == '__main__':
    td = TestData("./data")
    data = td.get_test_data(1)
    print(data)
