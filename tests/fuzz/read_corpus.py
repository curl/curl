#!/usr/bin/env python
#
# Simple script which reads corpus files.

import argparse
import logging
import sys
import corpus
log = logging.getLogger(__name__)


def read_corpus(options):
    with open(options.input, "rb") as f:
        dec = corpus.TLVDecoder(f.read())
        for tlv in dec:
            print(tlv)

    return ScriptRC.SUCCESS


def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    return parser.parse_args()


def setup_logging():
    """
    Set up logging from the command line options
    """
    root_logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s %(levelname)-5.5s %(message)s")
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(stdout_handler)
    root_logger.setLevel(logging.DEBUG)


class ScriptRC(object):
    """Enum for script return codes"""
    SUCCESS = 0
    FAILURE = 1
    EXCEPTION = 2


class ScriptException(Exception):
    pass


def main():
    # Get the options from the user.
    options = get_options()

    setup_logging()

    # Run main script.
    try:
        rc = read_corpus(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("Returning %d", rc)
    return rc


if __name__ == '__main__':
    sys.exit(main())
