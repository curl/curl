#!/usr/bin/env python
#
# Simple script which generates corpus files.

import argparse
import logging
import corpus
import sys
sys.path.append("..")
import curl_test_data
log = logging.getLogger(__name__)


def generate_corpus(options):
    td = curl_test_data.TestData("../data")

    with open(options.output, "wb") as f:
        enc = corpus.TLVEncoder(f)

        # Write the URL to the file.
        enc.write_string(enc.TYPE_URL, options.url)

        # Write the first response to the file.
        if options.rsp1:
            enc.write_bytes(enc.TYPE_RSP1, options.rsp1.encode("utf-8"))

        elif options.rsp1file:
            with open(options.rsp1file, "rb") as g:
                enc.write_bytes(enc.TYPE_RSP1, g.read())

        elif options.rsp1test:
            wstring = td.get_test_data(options.rsp1test)
            enc.write_bytes(enc.TYPE_RSP1, wstring.encode("utf-8"))

        # Write other options to file.
        enc.maybe_write_string(enc.TYPE_USERNAME, options.username)
        enc.maybe_write_string(enc.TYPE_PASSWORD, options.password)
        enc.maybe_write_string(enc.TYPE_POSTFIELDS, options.postfields)
        enc.maybe_write_string(enc.TYPE_COOKIE, options.cookie)
        enc.maybe_write_string(enc.TYPE_RANGE, options.range)
        enc.maybe_write_string(enc.TYPE_CUSTOMREQUEST, options.customrequest)
        enc.maybe_write_string(enc.TYPE_MAIL_FROM, options.mailfrom)

        # Write the first upload to the file.
        if options.upload1:
            enc.write_bytes(enc.TYPE_UPLOAD1, options.upload1.encode("utf-8"))
        elif options.upload1file:
            with open(options.upload1file, "rb") as g:
                enc.write_bytes(enc.TYPE_UPLOAD1, g.read())

        # Write an array of headers to the file.
        if options.header:
            for header in options.header:
                enc.write_string(enc.TYPE_HEADER, header)

        # Write an array of headers to the file.
        if options.mailrecipient:
            for mailrecipient in options.mailrecipient:
                enc.write_string(enc.TYPE_MAIL_RECIPIENT, mailrecipient)

    return ScriptRC.SUCCESS


def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--postfields")
    parser.add_argument("--header", action="append")
    parser.add_argument("--cookie")
    parser.add_argument("--range")
    parser.add_argument("--customrequest")
    parser.add_argument("--mailfrom")
    parser.add_argument("--mailrecipient", action="append")

    rsp1 = parser.add_mutually_exclusive_group(required=True)
    rsp1.add_argument("--rsp1")
    rsp1.add_argument("--rsp1file")
    rsp1.add_argument("--rsp1test", type=int)

    upload1 = parser.add_mutually_exclusive_group()
    upload1.add_argument("--upload1")
    upload1.add_argument("--upload1file")

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
        rc = generate_corpus(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("Returning %d", rc)
    return rc


if __name__ == '__main__':
    sys.exit(main())
