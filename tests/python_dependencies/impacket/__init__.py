# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#

# Set default logging handler to avoid "No handler found" warnings.
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

# All modules inside this library MUST use this logger (impacket)
# It is up to the library consumer to do whatever is wanted 
# with the logger output. By default it is forwarded to the 
# upstream logger

LOG = logging.getLogger(__name__)
LOG.addHandler(NullHandler())
