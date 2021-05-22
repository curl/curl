#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2017 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
"""Module for extracting test data from the test data folder and other utils"""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import logging
import os
import re

log = logging.getLogger(__name__)


REPLY_DATA = re.compile("<reply>[ \t\n\r]*<data[^<]*>(.*?)</data>", re.MULTILINE | re.DOTALL)


class ClosingFileHandler(logging.StreamHandler):
    def __init__(self, filename):
        super(ClosingFileHandler, self).__init__()
        self.filename = os.path.abspath(filename)
        self.setStream(None)

    def emit(self, record):
        with open(self.filename, "a") as fp:
            self.setStream(fp)
            super(ClosingFileHandler, self).emit(record)
            self.setStream(None)

    def setStream(self, stream):
        setStream = getattr(super(ClosingFileHandler, self), 'setStream', None)
        if callable(setStream):
            return setStream(stream)
        if stream is self.stream:
            result = None
        else:
            result = self.stream
            self.acquire()
            try:
                self.flush()
                self.stream = stream
            finally:
                self.release()
        return result

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
