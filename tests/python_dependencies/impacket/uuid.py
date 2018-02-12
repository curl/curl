# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Generate UUID compliant with http://www.webdav.org/specs/draft-leach-uuids-guids-01.txt.
#   A different, much simpler (not necessarily better) algorithm is used.
#
# Author:
#   Javier Kohen (jkohen)
#

import re

from random import randrange
from struct import pack, unpack

def generate():
    # UHm... crappy Python has an maximum integer of 2**31-1.
    top = (1L<<31)-1
    return pack("IIII", randrange(top), randrange(top), randrange(top), randrange(top))

def bin_to_string(uuid):
    uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
    uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
    return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)

def string_to_bin(uuid):
    matches = re.match('([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})', uuid)
    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: long(x, 16), matches.groups())
    uuid = pack('<LHH', uuid1, uuid2, uuid3)
    uuid += pack('>HHL', uuid4, uuid5, uuid6)
    return uuid

def stringver_to_bin(s):
    (maj,min) = s.split('.')
    return pack('<H',int(maj)) + pack('<H',int(min))

def uuidtup_to_bin(tup):
    if len(tup) != 2: return
    return string_to_bin(tup[0]) + stringver_to_bin(tup[1])

def bin_to_uuidtup(bin):
    assert len(bin) == 20
    uuidstr = bin_to_string(bin[:16])
    maj, min = unpack("<HH", bin[16:])
    return uuidstr, "%d.%d" % (maj, min)

#input: string
#output: tuple (uuid,version) 
#if version is not found in the input string "1.0"  is returned
#example: 
#           "00000000-0000-0000-0000-000000000000 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0') 
#           "10000000-2000-3000-4000-500000000000 version 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0') 
#           "10000000-2000-3000-4000-500000000000 v 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0') 
#           "10000000-2000-3000-4000-500000000000" returns ('00000000-0000-0000-0000-000000000000','1.0') 
def string_to_uuidtup(s):
    g =  re.search("([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}).*?([0-9]{1,5}\.[0-9]{1,5})",s+" 1.0")
    if g: 
        (u,v) = g.groups()
        return (u,v)
    return

def uuidtup_to_string(tup):
    uuid, (maj, min) = tup
    return "%s v%d.%d" % (uuid, maj, min)
