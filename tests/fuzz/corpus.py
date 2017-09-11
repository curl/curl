#!/usr/bin/env python
#
# Common corpus functions
import logging
import struct
log = logging.getLogger(__name__)


class BaseType(object):
    TYPE_URL = 1
    TYPE_RSP1 = 2
    TYPE_USERNAME = 3
    TYPE_PASSWORD = 4
    TYPE_POSTFIELDS = 5
    TYPE_HEADER = 6
    TYPE_COOKIE = 7
    TYPE_UPLOAD1 = 8
    TYPE_RANGE = 9
    TYPE_CUSTOMREQUEST = 10
    TYPE_MAIL_RECIPIENT = 11
    TYPE_MAIL_FROM = 12


class TLVEncoder(BaseType):
    def __init__(self, output):
        self.output = output

    def write_string(self, tlv_type, wstring):
        data = wstring.encode("utf-8")
        self.write_tlv(tlv_type, len(data), data)

    def write_bytes(self, tlv_type, bytedata):
        self.write_tlv(tlv_type, len(bytedata), bytedata)

    def maybe_write_string(self, tlv_type, wstring):
        if wstring is not None:
            self.write_string(tlv_type, wstring)

    def write_tlv(self, tlv_type, tlv_length, tlv_data=None):
        log.debug("Writing TLV %d, length %d, data %r",
                  tlv_type,
                  tlv_length,
                  tlv_data)

        data = struct.pack("!H", tlv_type)
        self.output.write(data)

        data = struct.pack("!L", tlv_length)
        self.output.write(data)

        if tlv_data:
            self.output.write(tlv_data)


class TLVDecoder(BaseType):
    def __init__(self, inputdata):
        self.inputdata = inputdata
        self.pos = 0
        self.tlv = None

    def __iter__(self):
        self.pos = 0
        self.tlv = None
        return self

    def __next__(self):
        if self.tlv:
            self.pos += self.tlv.total_length()

        if (self.pos + TLVHeader.TLV_DECODE_FMT_LEN) > len(self.inputdata):
            raise StopIteration

        # Get the next TLV
        self.tlv = TLVHeader(self.inputdata[self.pos:])
        return self.tlv

    next = __next__


class TLVHeader(BaseType):
    TLV_DECODE_FMT = "!HL"
    TLV_DECODE_FMT_LEN = struct.calcsize(TLV_DECODE_FMT)

    def __init__(self, data):
        # Parse the data to populate the TLV fields
        (self.type, self.length) = struct.unpack(self.TLV_DECODE_FMT, data[0:self.TLV_DECODE_FMT_LEN])

        # Get the remaining data and store it.
        self.data = data[self.TLV_DECODE_FMT_LEN:self.TLV_DECODE_FMT_LEN + self.length]

    def __repr__(self):
        return ("{self.__class__.__name__}(type={self.type!r}, length={self.length!r}, data={self.data!r})"
                .format(self=self))

    def total_length(self):
        return self.TLV_DECODE_FMT_LEN + self.length