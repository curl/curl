# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#


# -*- mode: python; tab-width: 4 -*-
#
# Copyright (C) 2001 Michael Teo <michaelteo@bigfoot.com>
# nmb.py - NetBIOS library
#
# This software is provided 'as-is', without any express or implied warranty. 
# In no event will the author be held liable for any damages arising from the 
# use of this software.
#
# Permission is granted to anyone to use this software for any purpose, 
# including commercial applications, and to alter it and redistribute it 
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not 
#    claim that you wrote the original software. If you use this software 
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be 
#    misrepresented as being the original software.
#
# 3. This notice cannot be removed or altered from any source distribution.
#
# Altered source done by Alberto Solino (@agsolino)

import socket
import string
import re
import select
import errno
from random import randint
from struct import pack, unpack
import time

from structure import Structure

CVS_REVISION = '$Revision: 526 $'

# Taken from socket module reference
INADDR_ANY = '0.0.0.0'
BROADCAST_ADDR = '<broadcast>'

# Default port for NetBIOS name service
NETBIOS_NS_PORT = 137
# Default port for NetBIOS session service
NETBIOS_SESSION_PORT = 139

# Default port for SMB session service
SMB_SESSION_PORT = 445

# Owner Node Type Constants
NODE_B = 0x0000
NODE_P = 0x2000
NODE_M = 0x4000
NODE_RESERVED = 0x6000
NODE_GROUP = 0x8000
NODE_UNIQUE = 0x0

# Name Type Constants
TYPE_UNKNOWN = 0x01
TYPE_WORKSTATION = 0x00
TYPE_CLIENT = 0x03
TYPE_SERVER = 0x20
TYPE_DOMAIN_MASTER = 0x1B
TYPE_DOMAIN_CONTROLLER = 0x1C
TYPE_MASTER_BROWSER = 0x1D
TYPE_BROWSER = 0x1E
TYPE_NETDDE  = 0x1F
TYPE_STATUS = 0x21

# Opcodes values
OPCODE_QUERY = 0
OPCODE_REGISTRATION = 0x5
OPCODE_RELEASE = 0x6
OPCODE_WACK = 0x7
OPCODE_REFRESH = 0x8
OPCODE_REQUEST = 0
OPCODE_RESPONSE = 0x10

# NM_FLAGS
NM_FLAGS_BROADCAST = 0x1
NM_FLAGS_UNICAST = 0
NM_FLAGS_RA = 0x8
NM_FLAGS_RD = 0x10
NM_FLAGS_TC = 0x20
NM_FLAGS_AA = 0x40

# QUESTION_TYPE
QUESTION_TYPE_NB = 0x20     # NetBIOS general Name Service Resource Record
QUESTION_TYPE_NBSTAT = 0x21 # NetBIOS NODE STATUS Resource Record
# QUESTION_CLASS
QUESTION_CLASS_IN = 0x1     # Internet class

# RR_TYPE Resource Record Type code
RR_TYPE_A = 0x1               # IP address Resource Record
RR_TYPE_NS = 0x2              # Name Server Resource Record
RR_TYPE_NULL = 0xA          # NULL Resource Record
RR_TYPE_NB = 0x20           # NetBIOS general Name Service Resource Record
RR_TYPE_NBSTAT = 0x21       # NetBIOS NODE STATUS Resource Record

# Resource Record Class
RR_CLASS_IN = 1             # Internet class

# RCODE values
RCODE_FMT_ERR   = 0x1       # Format Error.  Request was invalidly formatted.
RCODE_SRV_ERR   = 0x2       # Server failure.  Problem with NBNS, cannot process name.
RCODE_IMP_ERR   = 0x4       # Unsupported request error.  Allowable only for challenging NBNS when gets an Update type
                            # registration request.
RCODE_RFS_ERR   = 0x5       # Refused error.  For policy reasons server will not register this name from this host.
RCODE_ACT_ERR   = 0x6       # Active error.  Name is owned by another node.
RCODE_CFT_ERR   = 0x7       # Name in conflict error.  A UNIQUE name is owned by more than one node.

# NAME_FLAGS
NAME_FLAGS_PRM = 0x0200       # Permanent Name Flag.  If one (1) then entry is for the permanent node name.  Flag is zero
                            # (0) for all other names.
NAME_FLAGS_ACT = 0x0400       # Active Name Flag.  All entries have this flag set to one (1).
NAME_FLAG_CNF  = 0x0800       # Conflict Flag.  If one (1) then name on this node is in conflict.
NAME_FLAG_DRG  = 0x1000       # Deregister Flag.  If one (1) then this name is in the process of being deleted.

NAME_TYPES = { TYPE_UNKNOWN: 'Unknown', TYPE_WORKSTATION: 'Workstation', TYPE_CLIENT: 'Client',
               TYPE_SERVER: 'Server', TYPE_MASTER_BROWSER: 'Master Browser', TYPE_BROWSER: 'Browser Server',
               TYPE_DOMAIN_MASTER: 'Domain Master' , TYPE_NETDDE: 'NetDDE Server'}
# NetBIOS Session Types
NETBIOS_SESSION_MESSAGE = 0x0
NETBIOS_SESSION_REQUEST = 0x81
NETBIOS_SESSION_POSITIVE_RESPONSE = 0x82
NETBIOS_SESSION_NEGATIVE_RESPONSE = 0x83
NETBIOS_SESSION_RETARGET_RESPONSE = 0x84
NETBIOS_SESSION_KEEP_ALIVE = 0x85


def strerror(errclass, errcode):
    if errclass == ERRCLASS_OS:
        return 'OS Error', str(errcode)
    elif errclass == ERRCLASS_QUERY:
        return 'Query Error', QUERY_ERRORS.get(errcode, 'Unknown error')
    elif errclass == ERRCLASS_SESSION:
        return 'Session Error', SESSION_ERRORS.get(errcode, 'Unknown error')
    else:
        return 'Unknown Error Class', 'Unknown Error'
    
    

class NetBIOSError(Exception): pass
class NetBIOSTimeout(Exception):
    def __init__(self, message = 'The NETBIOS connection with the remote host timed out.'):
        Exception.__init__(self, message)

class NBResourceRecord:
    def __init__(self, data = 0):
        self._data = data
        try:
            if self._data:
                self.rr_name = (re.split('\x00',data))[0]
                offset = len(self.rr_name)+1
                self.rr_type  = unpack('>H', self._data[offset:offset+2])[0]
                self.rr_class = unpack('>H', self._data[offset+2: offset+4])[0]
                self.ttl = unpack('>L',self._data[offset+4:offset+8])[0]
                self.rdlength = unpack('>H', self._data[offset+8:offset+10])[0]
                self.rdata = self._data[offset+10:offset+10+self.rdlength]
                offset = self.rdlength - 2
                self.unit_id = data[offset:offset+6]
            else:
                self.rr_name = ''
                self.rr_type = 0
                self.rr_class = 0
                self.ttl = 0
                self.rdlength = 0
                self.rdata = ''
                self.unit_id = ''
        except Exception:
                raise NetBIOSError( 'Wrong packet format ' )

    def set_rr_name(self, name):
        self.rr_name = name
    def set_rr_type(self, name):
        self.rr_type = name
    def set_rr_class(self,cl):
        self.rr_class = cl
    def set_ttl(self,ttl):
        self.ttl = ttl
    def set_rdata(self,rdata):
        self.rdata = rdata
        self.rdlength = len(rdata)
    def get_unit_id(self):
        return self.unit_id
    def get_rr_name(self):
        return self.rr_name
    def get_rr_class(self):
        return self.rr_class
    def get_ttl(self):
        return self.ttl
    def get_rdlength(self):
        return self.rdlength
    def get_rdata(self):
        return self.rdata
    def rawData(self):
        return self.rr_name + pack('!HHLH',self.rr_type, self.rr_class, self.ttl, self.rdlength) + self.rdata

class NBNodeStatusResponse(NBResourceRecord):
    def __init__(self, data = 0):
        NBResourceRecord.__init__(self,data)
        self.num_names = 0
        self.node_names = [ ]
        self.statstics = ''
        self.mac = '00-00-00-00-00-00'
        try:
            if data:
                self._data = self.get_rdata()
                self.num_names = unpack('>B',self._data[:1])[0]
                offset = 1
                for i in range(0, self.num_names):
                    name = self._data[offset:offset + 15]
                    type,flags = unpack('>BH', self._data[offset + 15: offset + 18])
                    offset += 18
                    self.node_names.append(NBNodeEntry(name, type ,flags))
                self.set_mac_in_hexa(self.get_unit_id())
        except Exception:
            raise NetBIOSError( 'Wrong packet format ' )

    def set_mac_in_hexa(self, data):
        data_aux = ''
        for d in data:
            if data_aux == '':
                data_aux = '%02x' % ord(d)
            else:
                data_aux += '-%02x' % ord(d)
        self.mac = string.upper(data_aux)

    def get_num_names(self):
        return self.num_names
    def get_mac(self):
        return self.mac
    def set_num_names(self, num):
        self.num_names = num
    def get_node_names(self):
        return self.node_names
    def add_node_name(self,node_names):
        self.node_names.append(node_names)
        self.num_names += 1
    def rawData(self):
        res = pack('!B', self.num_names )
        for i in range(0, self.num_names):
            res += self.node_names[i].rawData()

class NBPositiveNameQueryResponse(NBResourceRecord):
    def __init__(self, data = 0):
        NBResourceRecord.__init__(self, data)
        self.addr_entries = [ ]
        if data:
                self._data = self.get_rdata()
                _qn_length, qn_name, qn_scope = decode_name(data)
                self._netbios_name = string.rstrip(qn_name[:-1]) + qn_scope
                self._name_type = ord(qn_name[-1])
                self._nb_flags = unpack('!H', self._data[:2])
                offset = 2
                while offset<len(self._data):
                    self.addr_entries.append('%d.%d.%d.%d' % unpack('4B', (self._data[offset:offset+4])))
                    offset += 4
    
    def get_netbios_name(self):
        return self._netbios_name
    
    def get_name_type(self):
        return self._name_type
    
    def get_addr_entries(self):
        return self.addr_entries
                
class NetBIOSPacket:
    """ This is a packet as defined in RFC 1002 """
    def __init__(self, data = 0):
        self.name_trn_id = 0x0  # Transaction ID for Name Service Transaction.
                                #   Requestor places a unique value for each active
                                #   transaction.  Responder puts NAME_TRN_ID value
                                #   from request packet in response packet.
        self.opcode = 0         # Packet type code
        self.nm_flags = 0       # Flags for operation
        self.rcode = 0          # Result codes of request.
        self.qdcount = 0        # Unsigned 16 bit integer specifying the number of entries in the question section of a Name
        self.ancount = 0        # Unsigned 16 bit integer specifying the number of
                                # resource records in the answer section of a Name
                                # Service packet.
        self.nscount = 0        # Unsigned 16 bit integer specifying the number of
                                # resource records in the authority section of a
                                # Name Service packet.
        self.arcount = 0        # Unsigned 16 bit integer specifying the number of
                                # resource records in the additional records
                                # section of a Name Service packeT.
        self.questions = ''
        self.answers = ''
        if data == 0:
            self._data = ''
        else:
            try:
                self._data = data
                self.opcode = ord(data[2]) >> 3 
                self.nm_flags = ((ord(data[2]) & 0x3) << 4) | ((ord(data[3]) & 0xf0) >> 4)
                self.name_trn_id = unpack('>H', self._data[:2])[0]
                self.rcode = ord(data[3]) & 0x0f
                self.qdcount = unpack('>H', self._data[4:6])[0]
                self.ancount = unpack('>H', self._data[6:8])[0]
                self.nscount = unpack('>H', self._data[8:10])[0]
                self.arcount = unpack('>H', self._data[10:12])[0]
                self.answers = self._data[12:]
            except Exception:
                raise NetBIOSError( 'Wrong packet format ' )
            
    def set_opcode(self, opcode):
        self.opcode = opcode
    def set_trn_id(self, trn):
        self.name_trn_id = trn
    def set_nm_flags(self, nm_flags):
        self.nm_flags = nm_flags
    def set_rcode(self, rcode):
        self.rcode = rcode
    def addQuestion(self, question, qtype, qclass):
        self.qdcount += 1
        self.questions += question + pack('!HH',qtype,qclass)
    def get_trn_id(self):
        return self.name_trn_id
    def get_rcode(self):
        return self.rcode
    def get_nm_flags(self):
        return self.nm_flags
    def get_opcode(self):
        return self.opcode
    def get_qdcount(self):
        return self.qdcount
    def get_ancount(self):
        return self.ancount
    def get_nscount(self):
        return self.nscount
    def get_arcount(self):
        return self.arcount
    def rawData(self):
        secondWord = self.opcode << 11
        secondWord |= self.nm_flags << 4
        secondWord |= self.rcode
        data = pack('!HHHHHH', self.name_trn_id, secondWord , self.qdcount, self.ancount, self.nscount, self.arcount) + self.questions + self.answers
        return data
    def get_answers(self):
        return self.answers

class NBHostEntry:

    def __init__(self, nbname, nametype, ip):
        self.__nbname = nbname
        self.__nametype = nametype
        self.__ip = ip

    def get_nbname(self):
        return self.__nbname

    def get_nametype(self):
        return self.__nametype

    def get_ip(self):
        return self.__ip

    def __repr__(self):
        return '<NBHostEntry instance: NBname="' + self.__nbname + '", IP="' + self.__ip + '">'

class NBNodeEntry:
    
    def __init__(self, nbname, nametype, flags): 
        self.__nbname = string.ljust(nbname,17)
        self.__nametype = nametype
        self.__flags = flags
        self.__isgroup = flags & 0x8000
        self.__nodetype = flags & 0x6000
        self.__deleting = flags & 0x1000
        self.__isconflict = flags & 0x0800
        self.__isactive = flags & 0x0400
        self.__ispermanent = flags & 0x0200

    def get_nbname(self):
        return self.__nbname

    def get_nametype(self):
        return self.__nametype

    def is_group(self):
        return self.__isgroup

    def get_nodetype(self):
        return self.__nodetype

    def is_deleting(self):
        return self.__deleting

    def is_conflict(self):
        return self.__isconflict

    def is_active(self):
        return self.__isactive

    def is_permanent(self):
        return self.__ispermanent

    def set_nbname(self, name):
        self.__nbname = string.ljust(name,17)

    def set_nametype(self, type):
        self.__nametype = type

    def set_flags(self,flags):
        self.__flags = flags
        
    def __repr__(self):
        s = '<NBNodeEntry instance: NBname="' + self.__nbname + '" NameType="' + NAME_TYPES[self.__nametype] + '"'
        if self.__isactive:
            s += ' ACTIVE'
        if self.__isgroup:
            s += ' GROUP'
        if self.__isconflict:
            s += ' CONFLICT'
        if self.__deleting:
            s += ' DELETING'
        return s
    def rawData(self):
        return self.__nbname + pack('!BH',self.__nametype, self.__flags)


class NetBIOS:

    # Creates a NetBIOS instance without specifying any default NetBIOS domain nameserver.
    # All queries will be sent through the servport.
    def __init__(self, servport = NETBIOS_NS_PORT):
        self.__servport = NETBIOS_NS_PORT
        self.__nameserver = None
        self.__broadcastaddr = BROADCAST_ADDR
        self.mac = '00-00-00-00-00-00'

    def _setup_connection(self, dstaddr):
        port = randint(10000, 60000)
        af, socktype, proto, _canonname, _sa = socket.getaddrinfo(dstaddr, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        s = socket.socket(af, socktype, proto)
        has_bind = 1
        for _i in range(0, 10):
        # We try to bind to a port for 10 tries
            try:
                s.bind(( INADDR_ANY, randint(10000, 60000) ))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                has_bind = 1
            except socket.error:
                pass
        if not has_bind:
            raise NetBIOSError, ( 'Cannot bind to a good UDP port', ERRCLASS_OS, errno.EAGAIN )
        self.__sock = s

    # Set the default NetBIOS domain nameserver.
    def set_nameserver(self, nameserver):
        self.__nameserver = nameserver

    # Return the default NetBIOS domain nameserver, or None if none is specified.
    def get_nameserver(self):
        return self.__nameserver

    # Set the broadcast address to be used for query.
    def set_broadcastaddr(self, broadcastaddr):
        self.__broadcastaddr = broadcastaddr

    # Return the broadcast address to be used, or BROADCAST_ADDR if default broadcast address is used.   
    def get_broadcastaddr(self):
        return self.__broadcastaddr

    # Returns a NBPositiveNameQueryResponse instance containing the host information for nbname.
    # If a NetBIOS domain nameserver has been specified, it will be used for the query.
    # Otherwise, the query is broadcasted on the broadcast address.
    def gethostbyname(self, nbname, qtype = TYPE_WORKSTATION, scope = None, timeout = 1):
        return self.__queryname(nbname, self.__nameserver, qtype, scope, timeout)

    # Returns a list of NBNodeEntry instances containing node status information for nbname.
    # If destaddr contains an IP address, then this will become an unicast query on the destaddr.
    # Raises NetBIOSTimeout if timeout (in secs) is reached.
    # Raises NetBIOSError for other errors
    def getnodestatus(self, nbname, destaddr = None, type = TYPE_WORKSTATION, scope = None, timeout = 1):
        if destaddr:
            return self.__querynodestatus(nbname, destaddr, type, scope, timeout)
        else:
            return self.__querynodestatus(nbname, self.__nameserver, type, scope, timeout)

    def getnetbiosname(self, ip):
        entries = self.getnodestatus('*',ip)
        entries = filter(lambda x:x.get_nametype() == TYPE_SERVER, entries)
        return entries[0].get_nbname().strip()

    def getmacaddress(self):
        return self.mac

    def __queryname(self, nbname, destaddr, qtype, scope, timeout, retries = 0):
        self._setup_connection(destaddr)
        trn_id = randint(1, 32000)
        p = NetBIOSPacket()
        p.set_trn_id(trn_id)
        netbios_name = nbname.upper()
        qn_label = encode_name(netbios_name, qtype, scope)
        p.addQuestion(qn_label, QUESTION_TYPE_NB, QUESTION_CLASS_IN)
        p.set_nm_flags(NM_FLAGS_RD)
        if not destaddr:
            p.set_nm_flags(p.get_nm_flags() | NM_FLAGS_BROADCAST)
            destaddr = self.__broadcastaddr            
        req = p.rawData()
        
        tries = retries
        while 1:
            self.__sock.sendto(req, ( destaddr, self.__servport ))
            try:
                ready, _, _ = select.select([ self.__sock.fileno() ], [ ] , [ ], timeout)
                if not ready:
                    if tries:
                        # Retry again until tries == 0
                        tries -= 1
                    else:
                        raise NetBIOSTimeout
                else:
                    data, _ = self.__sock.recvfrom(65536, 0)
                    
                    res = NetBIOSPacket(data)
                    if res.get_trn_id() == p.get_trn_id():
                        if res.get_rcode():
                            if res.get_rcode() == 0x03:
                                return None
                            else:
                                raise NetBIOSError, ( 'Negative name query response', ERRCLASS_QUERY, res.get_rcode() )
                        
                        if res.get_ancount() != 1:
                            raise NetBIOSError( 'Malformed response')
                        
                        return NBPositiveNameQueryResponse(res.get_answers())
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ( 'Error occurs while waiting for response', ERRCLASS_OS, ex[0] )
                raise


    def __querynodestatus(self, nbname, destaddr, type, scope, timeout):
        self._setup_connection(destaddr)
        trn_id = randint(1, 32000)
        p = NetBIOSPacket()
        p.set_trn_id(trn_id)
        netbios_name = string.upper(nbname)
        qn_label = encode_name(netbios_name, type, scope)
        p.addQuestion(qn_label, QUESTION_TYPE_NBSTAT, QUESTION_CLASS_IN)

        if not destaddr:
            p.set_nm_flags(NM_FLAGS_BROADCAST)
            destaddr = self.__broadcastaddr            
        req = p.rawData()
        tries = 3
        while 1:
            try:
                self.__sock.sendto(req, 0, ( destaddr, self.__servport ))
                ready, _, _ = select.select([ self.__sock.fileno() ], [ ] , [ ], timeout)
                if not ready:
                    if tries:
                        # Retry again until tries == 0
                        tries -= 1
                    else:
                        raise NetBIOSTimeout
                else:
                    try:
                        data, _ = self.__sock.recvfrom(65536, 0)
                    except Exception, e:
                        raise NetBIOSError, "recvfrom error: %s" % str(e)
                    self.__sock.close()
                    res = NetBIOSPacket(data)
                    if res.get_trn_id() == p.get_trn_id():
                        if res.get_rcode():
                            if res.get_rcode() == 0x03:
                                # I'm just guessing here
                                raise NetBIOSError, "Cannot get data from server"
                            else:
                                raise NetBIOSError, ( 'Negative name query response', ERRCLASS_QUERY, res.get_rcode() )
                        answ = NBNodeStatusResponse(res.get_answers())
                        self.mac = answ.get_mac()
                        return answ.get_node_names()
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ( 'Error occurs while waiting for response', ERRCLASS_OS, ex[0] )
            except socket.error, ex:
                raise NetBIOSError, 'Connection error: %s' % str(ex)

# Perform first and second level encoding of name as specified in RFC 1001 (Section 4)
def encode_name(name, type, scope):
    if name == '*':
        name += '\0' * 15
    elif len(name) > 15:
        name = name[:15] + chr(type)
    else:
        name = string.ljust(name, 15) + chr(type)
        
    encoded_name = chr(len(name) * 2) + re.sub('.', _do_first_level_encoding, name)
    if scope:
        encoded_scope = ''
        for s in string.split(scope, '.'):
            encoded_scope = encoded_scope + chr(len(s)) + s
        return encoded_name + encoded_scope + '\0'
    else:
        return encoded_name + '\0'

# Internal method for use in encode_name()
def _do_first_level_encoding(m):
    s = ord(m.group(0))
    return string.uppercase[s >> 4] + string.uppercase[s & 0x0f]

def decode_name(name):
    name_length = ord(name[0])
    assert name_length == 32

    decoded_name = re.sub('..', _do_first_level_decoding, name[1:33])
    if name[33] == '\0':
        return 34, decoded_name, ''
    else:
        decoded_domain = ''
        offset = 34
        while 1:
            domain_length = ord(name[offset])
            if domain_length == 0:
                break
            decoded_domain = '.' + name[offset:offset + domain_length]
            offset += domain_length
        return offset + 1, decoded_name, decoded_domain

def _do_first_level_decoding(m):
    s = m.group(0)
    return chr(((ord(s[0]) - ord('A')) << 4) | (ord(s[1]) - ord('A')))



class NetBIOSSessionPacket:
    def __init__(self, data = 0):
        self.type = 0x0 
        self.flags = 0x0
        self.length = 0x0
        if data == 0:
            self._trailer = ''
        else:
            try:
                self.type = ord(data[0])
                if self.type == NETBIOS_SESSION_MESSAGE:
                    self.length = ord(data[1]) << 16 | (unpack('!H', data[2:4])[0])
                else:
                    self.flags = ord(data[1])
                    self.length = unpack('!H', data[2:4])[0]

                self._trailer = data[4:]
            except:
                raise NetBIOSError( 'Wrong packet format ' )

    def set_type(self, type):
        self.type = type
    def get_type(self):
        return self.type
    def rawData(self):
        if self.type == NETBIOS_SESSION_MESSAGE:
            data = pack('!BBH',self.type,self.length >> 16,self.length & 0xFFFF) + self._trailer
        else:
            data = pack('!BBH',self.type,self.flags,self.length) + self._trailer
        return data
    def set_trailer(self,data):
        self._trailer = data
        self.length = len(data)
    def get_length(self):
        return self.length
    def get_trailer(self):
        return self._trailer
        
class NetBIOSSession:
    def __init__(self, myname, remote_name, remote_host, remote_type = TYPE_SERVER, sess_port = NETBIOS_SESSION_PORT, timeout = None, local_type = TYPE_WORKSTATION, sock = None):
        if len(myname) > 15:
            self.__myname = string.upper(myname[:15])
        else:
            self.__myname = string.upper(myname)
        self.__local_type = local_type

        assert remote_name
        # if destination port SMB_SESSION_PORT and remote name *SMBSERVER, we're changing it to its IP address
        # helping solving the client mistake ;)
        if remote_name == '*SMBSERVER' and sess_port == SMB_SESSION_PORT:
            remote_name = remote_host 
        # If remote name is *SMBSERVER let's try to query its name.. if can't be guessed, continue and hope for the best
        if remote_name == '*SMBSERVER':
            nb = NetBIOS()
            
            try:
                res = nb.getnetbiosname(remote_host)
            except:
                res = None
                pass 
            
            if res is not None:
                remote_name = res

        if len(remote_name) > 15:
            self.__remote_name = string.upper(remote_name[:15])
        else:
            self.__remote_name = string.upper(remote_name)
        self.__remote_type = remote_type

        self.__remote_host = remote_host

        if sock is not None:
            # We are acting as a server
            self._sock = sock
        else:
            self._sock = self._setup_connection((remote_host, sess_port))

        if sess_port == NETBIOS_SESSION_PORT:
            self._request_session(remote_type, local_type, timeout)

    def get_myname(self):
        return self.__myname

    def get_mytype(self):
        return self.__local_type

    def get_remote_host(self):
        return self.__remote_host

    def get_remote_name(self):
        return self.__remote_name

    def get_remote_type(self):
        return self.__remote_type

    def close(self):
        self._sock.close()

    def get_socket(self):
        return self._sock

class NetBIOSUDPSessionPacket(Structure):
    TYPE_DIRECT_UNIQUE = 16
    TYPE_DIRECT_GROUP  = 17

    FLAGS_MORE_FRAGMENTS = 1
    FLAGS_FIRST_FRAGMENT = 2
    FLAGS_B_NODE         = 0

    structure = (
        ('Type','B=16'),    # Direct Unique Datagram
        ('Flags','B=2'),    # FLAGS_FIRST_FRAGMENT
        ('ID','<H'),
        ('_SourceIP','>L'),
        ('SourceIP','"'),
        ('SourcePort','>H=138'),
        ('DataLegth','>H-Data'),
        ('Offset','>H=0'),
        ('SourceName','z'),
        ('DestinationName','z'),
        ('Data',':'),
    )

    def getData(self):
        addr = self['SourceIP'].split('.')
        addr = [int(x) for x in addr]
        addr = (((addr[0] << 8) + addr[1] << 8) + addr[2] << 8) + addr[3]
        self['_SourceIP'] = addr
        return Structure.getData(self)

    def get_trailer(self):
        return self['Data']

class NetBIOSUDPSession(NetBIOSSession):
    def _setup_connection(self, peer):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_DGRAM)[0]
        sock = socket.socket(af, socktype, proto)
        sock.connect(sa)

        sock = socket.socket(af, socktype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((INADDR_ANY, 138))
        self.peer = peer
        return sock

    def _request_session(self, remote_type, local_type, timeout = None):
        pass

    def next_id(self):
        if hasattr(self, '__dgram_id'):
            answer = self.__dgram_id
        else:
            self.__dgram_id = randint(1,65535)
            answer = self.__dgram_id
        self.__dgram_id += 1
        return answer

    def send_packet(self, data):
        # Yes... I know...
        self._sock.connect(self.peer)

        p = NetBIOSUDPSessionPacket()
        p['ID'] = self.next_id()
        p['SourceIP'] = self._sock.getsockname()[0]
        p['SourceName'] = encode_name(self.get_myname(), self.get_mytype(), '')[:-1]
        p['DestinationName'] = encode_name(self.get_remote_name(), self.get_remote_type(), '')[:-1]
        p['Data'] = data

        self._sock.sendto(str(p), self.peer)
        self._sock.close()

        self._sock = self._setup_connection(self.peer)

    def recv_packet(self, timeout = None):
        # The next loop is a workaround for a bigger problem:
        # When data reaches higher layers, the lower headers are lost,
        # and with them, for example, the source IP. Hence, SMB users
        # can't know where packets are comming from... we need a better
        # solution, right now, we will filter everything except packets
        # coming from the remote_host specified in __init__()

        while 1:
            data, peer = self._sock.recvfrom(8192)
#            print "peer: %r  self.peer: %r" % (peer, self.peer)
            if peer == self.peer: break

        return NetBIOSUDPSessionPacket(data)

class NetBIOSTCPSession(NetBIOSSession):
    def __init__(self, myname, remote_name, remote_host, remote_type = TYPE_SERVER, sess_port = NETBIOS_SESSION_PORT, timeout = None, local_type = TYPE_WORKSTATION, sock = None, select_poll = False):
        self.__select_poll = select_poll
        if self.__select_poll:
            self.read_function = self.polling_read
        else:
            self.read_function = self.non_polling_read
        NetBIOSSession.__init__(self, myname, remote_name, remote_host, remote_type = remote_type, sess_port = sess_port, timeout = timeout, local_type = local_type, sock=sock)                


    def _setup_connection(self, peer):
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(peer[0], peer[1], 0, socket.SOCK_STREAM)[0]
            sock = socket.socket(af, socktype, proto)
            sock.connect(sa)
        except socket.error, e:
            raise socket.error("Connection error (%s:%s)" % (peer[0], peer[1]), e)
        return sock

    def send_packet(self, data):
        p = NetBIOSSessionPacket()
        p.set_type(NETBIOS_SESSION_MESSAGE)
        p.set_trailer(data)
        self._sock.send(p.rawData())

    def recv_packet(self, timeout = None):
        data = self.__read(timeout)
        return NetBIOSSessionPacket(data)

    def _request_session(self, remote_type, local_type, timeout = None):
        p = NetBIOSSessionPacket()
        remote_name = encode_name(self.get_remote_name(), remote_type, '')
        myname = encode_name(self.get_myname(), local_type, '')
        p.set_type(NETBIOS_SESSION_REQUEST)
        p.set_trailer(remote_name + myname)

        self._sock.send(p.rawData())
        while 1:
            p = self.recv_packet(timeout)
            if p.get_type() == NETBIOS_SESSION_NEGATIVE_RESPONSE:
                raise NetBIOSError, ( 'Cannot request session', ERRCLASS_SESSION, ord(p.get_trailer()[0]) )
            elif p.get_type() == NETBIOS_SESSION_POSITIVE_RESPONSE:
                break
            else:
                # Ignore all other messages, most probably keepalive messages
                pass

    def polling_read(self, read_length, timeout):
        data = ''
        if timeout is None:
            timeout = 3600

        time_left = timeout
        CHUNK_TIME = 0.025
        bytes_left = read_length

        while bytes_left > 0:
            try:
                ready, _, _ = select.select([self._sock.fileno() ], [ ], [ ], 0)
                
                if not ready:
                    if time_left <= 0:
                        raise NetBIOSTimeout
                    else:
                        time.sleep(CHUNK_TIME)
                        time_left -= CHUNK_TIME
                        continue

                received = self._sock.recv(bytes_left)
                if len(received) == 0:
                    raise NetBIOSError, ( 'Error while reading from remote', ERRCLASS_OS, None)

                data = data + received
                bytes_left = read_length - len(data)
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ( 'Error occurs while reading from remote', ERRCLASS_OS, ex[0] )

        return data

    def non_polling_read(self, read_length, timeout):
        data = ''
        bytes_left = read_length

        while bytes_left > 0:
            try:
                ready, _, _ = select.select([self._sock.fileno() ], [ ], [ ], timeout)

                if not ready:
                        raise NetBIOSTimeout

                received = self._sock.recv(bytes_left)
                if len(received) == 0:
                    raise NetBIOSError, ( 'Error while reading from remote', ERRCLASS_OS, None)

                data = data + received
                bytes_left = read_length - len(data)
            except select.error, ex:
                if ex[0] != errno.EINTR and ex[0] != errno.EAGAIN:
                    raise NetBIOSError, ( 'Error occurs while reading from remote', ERRCLASS_OS, ex[0] )

        return data

    def __read(self, timeout = None):
        data = self.read_function(4, timeout)
        type, flags, length = unpack('>ccH', data)
        if ord(type) == NETBIOS_SESSION_MESSAGE:
            length |= ord(flags) << 16
        else:
            if ord(flags) & 0x01:
                length |= 0x10000
        data2 = self.read_function(length, timeout)

        return data + data2

ERRCLASS_QUERY = 0x00
ERRCLASS_SESSION = 0xf0
ERRCLASS_OS = 0xff

QUERY_ERRORS = { 0x01: 'Request format error. Please file a bug report.',
                 0x02: 'Internal server error',
                 0x03: 'Name does not exist',
                 0x04: 'Unsupported request',
                 0x05: 'Request refused'
                 }

SESSION_ERRORS = { 0x80: 'Not listening on called name',
                   0x81: 'Not listening for calling name',
                   0x82: 'Called name not present',
                   0x83: 'Sufficient resources',
                   0x8f: 'Unspecified error'
                   }

def main():
    def get_netbios_host_by_name(name):
        n = NetBIOS()
        n.set_broadcastaddr('255.255.255.255') # To avoid use "<broadcast>" in socket
        for qtype in (TYPE_WORKSTATION, TYPE_CLIENT, TYPE_SERVER, TYPE_DOMAIN_MASTER, TYPE_DOMAIN_CONTROLLER):
            try:
                addrs = n.gethostbyname(name, qtype = qtype).get_addr_entries()
            except NetBIOSTimeout:
                continue
            else:
                return addrs
        raise Exception("Host not found")
                
    
    n = get_netbios_host_by_name("some-host")
    print n

if __name__ == '__main__':
    main()
