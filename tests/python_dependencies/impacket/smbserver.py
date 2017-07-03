# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# TODO:
# [-] Functions should return NT error codes
# [-] Handling errors in all situations, right now it's just raising exceptions.
# [*] Standard authentication support
# [ ] Organize the connectionData stuff
# [*] Add capability to send a bad user ID if the user is not authenticated,
#     right now you can ask for any command without actually being authenticated
# [ ] PATH TRAVERSALS EVERYWHERE.. BE WARNED!
# [ ] Check the credentials.. now we're just letting everybody to log in.
# [ ] Check error situation (now many places assume the right data is coming)
# [ ] Implement IPC to the main process so the connectionData is on a single place
# [ ] Hence.. implement locking
# estamos en la B

from __future__ import with_statement
import calendar
import socket
import time
import datetime
import struct
import ConfigParser
import SocketServer
import threading
import logging
import logging.config
import ntpath
import os
import fnmatch
import errno
import sys
import random
import shutil
from binascii import hexlify

# For signing
from impacket import smb, nmb, ntlm, uuid, LOG
from impacket import smb3structs as smb2
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, MechTypes, SPNEGO_NegTokenResp, ASN1_AID, ASN1_SUPPORTED_MECH
from impacket.nt_errors import STATUS_NO_MORE_FILES, STATUS_NETWORK_NAME_DELETED, STATUS_INVALID_PARAMETER, \
    STATUS_FILE_CLOSED, STATUS_MORE_PROCESSING_REQUIRED, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_DIRECTORY_NOT_EMPTY, \
    STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_IMPLEMENTED, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_COLLISION, \
    STATUS_NO_SUCH_FILE, STATUS_CANCELLED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_ACCESS_DENIED, \
    STATUS_NOT_SUPPORTED, STATUS_INVALID_DEVICE_REQUEST, STATUS_FS_DRIVER_REQUIRED, STATUS_INVALID_INFO_CLASS

# These ones not defined in nt_errors
STATUS_SMB_BAD_UID = 0x005B0002
STATUS_SMB_BAD_TID = 0x00050002

# Utility functions
# and general functions.
# There are some common functions that can be accessed from more than one SMB
# command (or either TRANSACTION). That's why I'm putting them here
# TODO: Return NT ERROR Codes

def outputToJohnFormat(challenge, username, domain, lmresponse, ntresponse):
# We don't want to add a possible failure here, since this is an
# extra bonus. We try, if it fails, returns nothing
    ret_value = ''
    try:
        if len(ntresponse) > 24:
            # Extended Security - NTLMv2
            ret_value = {'hash_string':'%s::%s:%s:%s:%s' % (username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(challenge), hexlify(ntresponse)[:32], hexlify(ntresponse)[32:]), 'hash_version':'ntlmv2'}
        else:
            # NTLMv1
            ret_value = {'hash_string':'%s::%s:%s:%s:%s' % (username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(lmresponse), hexlify(ntresponse), hexlify(challenge)), 'hash_version':'ntlm'}
    except:
        # Let's try w/o decoding Unicode
        try:
            if len(ntresponse) > 24:
                # Extended Security - NTLMv2
                ret_value = {'hash_string':'%s::%s:%s:%s:%s' % (username, domain, hexlify(challenge), hexlify(ntresponse)[:32], hexlify(ntresponse)[32:]), 'hash_version':'ntlmv2'}
            else:
                # NTLMv1
                ret_value = {'hash_string':'%s::%s:%s:%s:%s' % (username, domain, hexlify(lmresponse), hexlify(ntresponse), hexlify(challenge)), 'hash_version':'ntlm'}
        except Exception, e:
            LOG.error("outputToJohnFormat: %s" % e)
            pass

    return ret_value

def writeJohnOutputToFile(hash_string, hash_version, file_name):
    fn_data = os.path.splitext(file_name)
    if hash_version == "ntlmv2":
        output_filename = fn_data[0] + "_ntlmv2" + fn_data[1]
    else:
        output_filename = fn_data[0] + "_ntlm" + fn_data[1]

    with open(output_filename,"a") as f:
            f.write(hash_string)
            f.write('\n')


def decodeSMBString( flags, text ):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return text.decode('utf-16le')
    else:
        return text

def encodeSMBString( flags, text ):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return (text).encode('utf-16le')
    else:
        return text

def getFileTime(t):
    t *= 10000000
    t += 116444736000000000
    return t

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

def getSMBDate(t):
    # TODO: Fix this :P
    d = datetime.date.fromtimestamp(t)
    year = d.year - 1980
    ret = (year << 8) + (d.month << 4) + d.day
    return ret

def getSMBTime(t):
    # TODO: Fix this :P
    d = datetime.datetime.fromtimestamp(t)
    return (d.hour << 8) + (d.minute << 4) + d.second

def getShares(connId, smbServer):
    config = smbServer.getServerConfig()
    sections = config.sections()
    # Remove the global one
    del(sections[sections.index('global')])
    shares = {}
    for i in sections:
        shares[i] = dict(config.items(i))
    return shares

def searchShare(connId, share, smbServer):
    config = smbServer.getServerConfig()
    if config.has_section(share):
       return dict(config.items(share))
    else:
       return None

def openFile(path,fileName, accessMode, fileAttributes, openMode):
    fileName = os.path.normpath(fileName.replace('\\','/'))
    errorCode = 0
    if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    mode = 0
    # Check the Open Mode
    if openMode & 0x10:
        # If the file does not exist, create it.
        mode = os.O_CREAT
    else:
        # If file does not exist, return an error
        if os.path.exists(pathName) is not True:
            errorCode = STATUS_NO_SUCH_FILE
            return 0,mode, pathName, errorCode

    if os.path.isdir(pathName) and (fileAttributes & smb.ATTR_DIRECTORY) == 0:
        # Request to open a normal file and this is actually a directory
            errorCode = STATUS_FILE_IS_A_DIRECTORY
            return 0, mode, pathName, errorCode
    # Check the Access Mode
    if accessMode & 0x7 == 1:
       mode |= os.O_WRONLY
    elif accessMode & 0x7 == 2:
       mode |= os.O_RDWR
    else:
       mode = os.O_RDONLY

    try:
        if sys.platform == 'win32':
            mode |= os.O_BINARY
        fid = os.open(pathName, mode)
    except Exception, e:
        LOG.error("openFile: %s,%s" % (pathName, mode) ,e)
        fid = 0
        errorCode = STATUS_ACCESS_DENIED

    return fid, mode, pathName, errorCode

def queryFsInformation(path, filename, level=0):

    if isinstance(filename,unicode):
         encoding = 'utf-16le'
         flags    = smb.SMB.FLAGS2_UNICODE
    else:
         encoding = 'ascii'
         flags    = 0

    fileName = os.path.normpath(filename.replace('\\','/'))
    if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    fileSize = os.path.getsize(pathName)
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
    if level == smb.SMB_QUERY_FS_ATTRIBUTE_INFO or level == smb2.SMB2_FILESYSTEM_ATTRIBUTE_INFO:
        data = smb.SMBQueryFsAttributeInfo()
        data['FileSystemAttributes']      = smb.FILE_CASE_SENSITIVE_SEARCH | smb.FILE_CASE_PRESERVED_NAMES
        data['MaxFilenNameLengthInBytes'] = 255
        data['LengthOfFileSystemName']    = len('XTFS')*2
        data['FileSystemName']            = 'XTFS'.encode('utf-16le')
        return data.getData()
    elif level == smb.SMB_INFO_VOLUME:
        data = smb.SMBQueryFsInfoVolume( flags = flags )
        data['VolumeLabel']               = 'SHARE'.encode(encoding)
        return data.getData()
    elif level == smb.SMB_QUERY_FS_VOLUME_INFO or level == smb2.SMB2_FILESYSTEM_VOLUME_INFO:
        data = smb.SMBQueryFsVolumeInfo()
        data['VolumeLabel']               = ''
        data['VolumeCreationTime']        = getFileTime(ctime)
        return data.getData()
    elif level == smb.SMB_QUERY_FS_SIZE_INFO:
        data = smb.SMBQueryFsSizeInfo()
        return data.getData()
    elif level == smb.FILE_FS_FULL_SIZE_INFORMATION:
        data = smb.SMBFileFsFullSizeInformation()
        return data.getData()
    elif level == smb.FILE_FS_SIZE_INFORMATION:
        data = smb.FileFsSizeInformation()
        return data.getData()
    else:
        lastWriteTime = mtime
        attribs = 0
        if os.path.isdir(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_DIRECTORY
        if os.path.isfile(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_NORMAL
        fileAttributes = attribs
        return fileSize, lastWriteTime, fileAttributes

def findFirst2(path, fileName, level, searchAttributes, isSMB2 = False):
     # TODO: Depending on the level, this could be done much simpler

     #print "FindFirs2 path:%s, filename:%s" % (path, fileName)
     fileName = os.path.normpath(fileName.replace('\\','/'))
     # Let's choose the right encoding depending on the request
     if isinstance(fileName,unicode):
         encoding = 'utf-16le'
         flags    = smb.SMB.FLAGS2_UNICODE
     else:
         encoding = 'ascii'
         flags    = 0

     if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
        # strip leading '/'
        fileName = fileName[1:]

     pathName = os.path.join(path,fileName)
     files = []

     if pathName.find('*') == -1 and pathName.find('?') == -1:
         # No search patterns
         pattern = ''
     else:
         pattern = os.path.basename(pathName)
         dirName = os.path.dirname(pathName)

     # Always add . and .. Not that important for Windows, but Samba whines if
     # not present (for * search only)
     if pattern == '*':
         files.append(os.path.join(dirName,'.'))
         files.append(os.path.join(dirName,'..'))

     if pattern != '':
         for file in os.listdir(dirName):
             if fnmatch.fnmatch(file.lower(),pattern.lower()):
                entry = os.path.join(dirName, file)
                if os.path.isdir(entry):
                    if searchAttributes & smb.ATTR_DIRECTORY:
                        files.append(entry)
                else:
                    files.append(entry)
     else:
         if os.path.exists(pathName):
             files.append(pathName)

     searchResult = []
     searchCount = len(files)
     errorCode = STATUS_SUCCESS

     for i in files:
        if level == smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileBothDirectoryInfo( flags = flags )
        elif level == smb.SMB_FIND_FILE_DIRECTORY_INFO or level == smb2.SMB2_FILE_DIRECTORY_INFO:
            item = smb.SMBFindFileDirectoryInfo( flags = flags )
        elif level == smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO or level == smb2.SMB2_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileFullDirectoryInfo( flags = flags )
        elif level == smb.SMB_FIND_INFO_STANDARD:
            item = smb.SMBFindInfoStandard( flags = flags )
        elif level == smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO or level == smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileIdFullDirectoryInfo( flags = flags )
        elif level == smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileIdBothDirectoryInfo( flags = flags )
        elif level == smb.SMB_FIND_FILE_NAMES_INFO or level == smb2.SMB2_FILE_NAMES_INFO:
            item = smb.SMBFindFileNamesInfo( flags = flags )
        else:
            LOG.error("Wrong level %d!" % level)
            return  searchResult, searchCount, STATUS_NOT_SUPPORTED

        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(i)
        if os.path.isdir(i):
           item['ExtFileAttributes'] = smb.ATTR_DIRECTORY
        else:
           item['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE

        item['FileName'] = os.path.basename(i).encode(encoding)

        if level == smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO or level == smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_BOTH_DIRECTORY_INFO:
           item['EaSize']            = 0
           item['EndOfFile']         = size
           item['AllocationSize']    = size
           item['CreationTime']      = getFileTime(ctime)
           item['LastAccessTime']    = getFileTime(atime)
           item['LastWriteTime']     = getFileTime(mtime)
           item['LastChangeTime']    = getFileTime(mtime)
           item['ShortName']         = '\x00'*24
           item['FileName']          = os.path.basename(i).encode(encoding)
           padLen = (8-(len(item) % 8)) % 8
           item['NextEntryOffset']   = len(item) + padLen
        elif level == smb.SMB_FIND_FILE_DIRECTORY_INFO:
           item['EndOfFile']         = size
           item['AllocationSize']    = size
           item['CreationTime']      = getFileTime(ctime)
           item['LastAccessTime']    = getFileTime(atime)
           item['LastWriteTime']     = getFileTime(mtime)
           item['LastChangeTime']    = getFileTime(mtime)
           item['FileName']          = os.path.basename(i).encode(encoding)
           padLen = (8-(len(item) % 8)) % 8
           item['NextEntryOffset']   = len(item) + padLen
        elif level == smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO or level == smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO or level == smb2.SMB2_FULL_DIRECTORY_INFO:
           item['EaSize']            = 0
           item['EndOfFile']         = size
           item['AllocationSize']    = size
           item['CreationTime']      = getFileTime(ctime)
           item['LastAccessTime']    = getFileTime(atime)
           item['LastWriteTime']     = getFileTime(mtime)
           item['LastChangeTime']    = getFileTime(mtime)
           padLen = (8-(len(item) % 8)) % 8
           item['NextEntryOffset']   = len(item) + padLen
        elif level == smb.SMB_FIND_INFO_STANDARD:
           item['EaSize']            = size
           item['CreationDate']      = getSMBDate(ctime)
           item['CreationTime']      = getSMBTime(ctime)
           item['LastAccessDate']    = getSMBDate(atime)
           item['LastAccessTime']    = getSMBTime(atime)
           item['LastWriteDate']     = getSMBDate(mtime)
           item['LastWriteTime']     = getSMBTime(mtime)
        searchResult.append(item)

     # No more files
     if (level >= smb.SMB_FIND_FILE_DIRECTORY_INFO or isSMB2 == True) and searchCount > 0:
         searchResult[-1]['NextEntryOffset'] = 0

     return searchResult, searchCount, errorCode

def queryFileInformation(path, filename, level):
    #print "queryFileInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
    return queryPathInformation(path,filename, level)

def queryPathInformation(path, filename, level):
    # TODO: Depending on the level, this could be done much simpler
  #print "queryPathInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
  try:
    errorCode = 0
    fileName = os.path.normpath(filename.replace('\\','/'))
    if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\') and path != '':
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    if os.path.exists(pathName):
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
        if level == smb.SMB_QUERY_FILE_BASIC_INFO:
            infoRecord = smb.SMBQueryFileBasicInfo()
            infoRecord['CreationTime']         = getFileTime(ctime)
            infoRecord['LastAccessTime']       = getFileTime(atime)
            infoRecord['LastWriteTime']        = getFileTime(mtime)
            infoRecord['LastChangeTime']       = getFileTime(mtime)
            if os.path.isdir(pathName):
               infoRecord['ExtFileAttributes'] = smb.ATTR_DIRECTORY
            else:
               infoRecord['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE
        elif level == smb.SMB_QUERY_FILE_STANDARD_INFO:
            infoRecord = smb.SMBQueryFileStandardInfo()
            infoRecord['AllocationSize']       = size
            infoRecord['EndOfFile']            = size
            if os.path.isdir(pathName):
               infoRecord['Directory']         = 1
            else:
               infoRecord['Directory']         = 0
        elif level == smb.SMB_QUERY_FILE_ALL_INFO or level == smb2.SMB2_FILE_ALL_INFO:
            infoRecord = smb.SMBQueryFileAllInfo()
            infoRecord['CreationTime']         = getFileTime(ctime)
            infoRecord['LastAccessTime']       = getFileTime(atime)
            infoRecord['LastWriteTime']        = getFileTime(mtime)
            infoRecord['LastChangeTime']       = getFileTime(mtime)
            if os.path.isdir(pathName):
               infoRecord['ExtFileAttributes'] = smb.ATTR_DIRECTORY
            else:
               infoRecord['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE
            infoRecord['AllocationSize']       = size
            infoRecord['EndOfFile']            = size
            if os.path.isdir(pathName):
               infoRecord['Directory']         = 1
            else:
               infoRecord['Directory']         = 0
            infoRecord['FileName']             = filename.encode('utf-16le')
        elif level == smb2.SMB2_FILE_NETWORK_OPEN_INFO:
            infoRecord = smb.SMBFileNetworkOpenInfo()
            infoRecord['CreationTime']         = getFileTime(ctime)
            infoRecord['LastAccessTime']       = getFileTime(atime)
            infoRecord['LastWriteTime']        = getFileTime(mtime)
            infoRecord['ChangeTime']           = getFileTime(mtime)
            infoRecord['AllocationSize']       = size
            infoRecord['EndOfFile']            = size
            if os.path.isdir(pathName):
               infoRecord['FileAttributes'] = smb.ATTR_DIRECTORY
            else:
               infoRecord['FileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE
        elif level == smb.SMB_QUERY_FILE_EA_INFO or level == smb2.SMB2_FILE_EA_INFO:
            infoRecord = smb.SMBQueryFileEaInfo()
        elif level == smb2.SMB2_FILE_STREAM_INFO:
            infoRecord = smb.SMBFileStreamInformation()
        else:
            LOG.error('Unknown level for query path info! 0x%x' % level)
            # UNSUPPORTED
            return None, STATUS_NOT_SUPPORTED

        return infoRecord, errorCode
    else:
        # NOT FOUND
        return None, STATUS_OBJECT_NAME_NOT_FOUND
  except Exception, e:
      LOG.error('queryPathInfo: %s' % e)
      raise

def queryDiskInformation(path):
# TODO: Do something useful here :)
# For now we just return fake values
   totalUnits = 65535
   freeUnits = 65535
   return totalUnits, freeUnits

# Here we implement the NT transaction handlers
class NTTRANSCommands:
    def default(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        pass

# Here we implement the NT transaction handlers
class TRANSCommands:
    @staticmethod
    def lanMan(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        # Minimal [MS-RAP] implementation, just to return the shares
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        if struct.unpack('<H',parameters[:2])[0] == 0:
            # NetShareEnum Request
            netShareEnum = smb.SMBNetShareEnum(parameters)
            if netShareEnum['InfoLevel'] == 1:
                shares = getShares(connId, smbServer)
                respParameters = smb.SMBNetShareEnumResponse()
                respParameters['EntriesReturned']  = len(shares)
                respParameters['EntriesAvailable'] = len(shares)
                tailData = ''
                for i in shares:
                    # NetShareInfo1 len == 20
                    entry = smb.NetShareInfo1()
                    entry['NetworkName'] = i + '\x00'*(13-len(i))
                    entry['Type']        = int(shares[i]['share type'])
                    # (beto) If offset == 0 it crashes explorer.exe on windows 7
                    entry['RemarkOffsetLow'] = 20 * len(shares) + len(tailData)
                    respData += entry.getData()
                    if shares[i].has_key('comment'):
                        tailData += shares[i]['comment'] + '\x00'
                    else:
                        tailData += '\x00'
                respData += tailData
            else:
                # We don't support other info levels
                errorCode = STATUS_NOT_SUPPORTED
        elif struct.unpack('<H',parameters[:2])[0] == 13:
            # NetrServerGetInfo Request
            respParameters = smb.SMBNetServerGetInfoResponse()
            netServerInfo = smb.SMBNetServerInfo1()
            netServerInfo['ServerName'] = smbServer.getServerName()
            respData = str(netServerInfo)
            respParameters['TotalBytesAvailable'] = len(respData)
        elif struct.unpack('<H',parameters[:2])[0] == 1:
            # NetrShareGetInfo Request
            request = smb.SMBNetShareGetInfo(parameters)
            respParameters = smb.SMBNetShareGetInfoResponse()
            shares = getShares(connId, smbServer)
            share = shares[request['ShareName'].upper()]
            shareInfo = smb.NetShareInfo1()
            shareInfo['NetworkName'] = request['ShareName'].upper() + '\x00'
            shareInfo['Type']        = int(share['share type'])
            respData = shareInfo.getData()
            if share.has_key('comment'):
                shareInfo['RemarkOffsetLow'] = len(respData)
                respData += share['comment'] + '\x00'
            respParameters['TotalBytesAvailable'] = len(respData)

        else:
            # We don't know how to handle anything else
            errorCode = STATUS_NOT_SUPPORTED

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def transactNamedPipe(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        SMBCommand  = smb.SMBCommand(recvPacket['Data'][0])
        transParameters= smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Extract the FID
        fid = struct.unpack('<H', transParameters['Setup'][2:])[0]

        if connData['OpenedFiles'].has_key(fid):
            fileHandle = connData['OpenedFiles'][fid]['FileHandle']
            if fileHandle != PIPE_FILE_DESCRIPTOR:
                os.write(fileHandle,data)
                respData = os.read(fileHandle,data)
            else:
                sock = connData['OpenedFiles'][fid]['Socket']
                sock.send(data)
                respData = sock.recv(maxDataCount)
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

# Here we implement the transaction2 handlers
class TRANS2Commands:
    # All these commands return setup, parameters, data, errorCode
    @staticmethod
    def setPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        setPathInfoParameters = smb.SMBSetPathInformation_Parameters(flags = recvPacket['Flags2'], data = parameters)
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path     = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = decodeSMBString(recvPacket['Flags2'], setPathInfoParameters['FileName'])
            fileName = os.path.normpath(fileName.replace('\\','/'))
            if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\') and path != '':
               # strip leading '/'
               fileName = fileName[1:]
            pathName = os.path.join(path,fileName)
            if os.path.exists(pathName):
                informationLevel = setPathInfoParameters['InformationLevel']
                if informationLevel == smb.SMB_SET_FILE_BASIC_INFO:
                    infoRecord = smb.SMBSetFileBasicInfo(data)
                    # Creation time won't be set,  the other ones we play with.
                    atime = infoRecord['LastAccessTime']
                    if atime == 0:
                        atime = -1
                    else:
                        atime = getUnixTime(atime)
                    mtime = infoRecord['LastWriteTime']
                    if mtime == 0:
                        mtime = -1
                    else:
                        mtime = getUnixTime(mtime)
                    if mtime != -1 or atime != -1:
                        os.utime(pathName,(atime,mtime))
                else:
                    smbServer.log('Unknown level for set path info! 0x%x' % setPathInfoParameters['InformationLevel'], logging.ERROR)
                    # UNSUPPORTED
                    errorCode =  STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_OBJECT_NAME_NOT_FOUND

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetPathInformationResponse_Parameters()

        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode


    @staticmethod
    def setFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        setFileInfoParameters = smb.SMBSetFileInformation_Parameters(parameters)

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            if connData['OpenedFiles'].has_key(setFileInfoParameters['FID']):
                fileName = connData['OpenedFiles'][setFileInfoParameters['FID']]['FileName']
                informationLevel = setFileInfoParameters['InformationLevel']
                if informationLevel == smb.SMB_SET_FILE_DISPOSITION_INFO:
                    infoRecord = smb.SMBSetFileDispositionInfo(parameters)
                    if infoRecord['DeletePending'] > 0:
                       # Mark this file for removal after closed
                       connData['OpenedFiles'][setFileInfoParameters['FID']]['DeleteOnClose'] = True
                       respParameters = smb.SMBSetFileInformationResponse_Parameters()
                elif informationLevel == smb.SMB_SET_FILE_BASIC_INFO:
                    infoRecord = smb.SMBSetFileBasicInfo(data)
                    # Creation time won't be set,  the other ones we play with.
                    atime = infoRecord['LastAccessTime']
                    if atime == 0:
                        atime = -1
                    else:
                        atime = getUnixTime(atime)
                    mtime = infoRecord['LastWriteTime']
                    if mtime == 0:
                        mtime = -1
                    else:
                        mtime = getUnixTime(mtime)
                    os.utime(fileName,(atime,mtime))
                elif informationLevel == smb.SMB_SET_FILE_END_OF_FILE_INFO:
                    fileHandle = connData['OpenedFiles'][setFileInfoParameters['FID']]['FileHandle']
                    infoRecord = smb.SMBSetFileEndOfFileInfo(data)
                    if infoRecord['EndOfFile'] > 0:
                        os.lseek(fileHandle, infoRecord['EndOfFile']-1, 0)
                        os.write(fileHandle, '\x00')
                else:
                    smbServer.log('Unknown level for set file info! 0x%x' % setFileInfoParameters['InformationLevel'], logging.ERROR)
                    # UNSUPPORTED
                    errorCode =  STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetFileInformationResponse_Parameters()
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''

        queryFileInfoParameters = smb.SMBQueryFileInformation_Parameters(parameters)

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            if connData['OpenedFiles'].has_key(queryFileInfoParameters['FID']):
                fileName = connData['OpenedFiles'][queryFileInfoParameters['FID']]['FileName']

                infoRecord, errorCode = queryFileInformation('', fileName, queryFileInfoParameters['InformationLevel'])

                if infoRecord is not None:
                    respParameters = smb.SMBQueryFileInformationResponse_Parameters()
                    respData = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = 0

        queryPathInfoParameters = smb.SMBQueryPathInformation_Parameters(flags = recvPacket['Flags2'], data = parameters)

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            try:
               infoRecord, errorCode = queryPathInformation(path, decodeSMBString(recvPacket['Flags2'], queryPathInfoParameters['FileName']), queryPathInfoParameters['InformationLevel'])
            except Exception, e:
               smbServer.log("queryPathInformation: %s" % e,logging.ERROR)

            if infoRecord is not None:
                respParameters = smb.SMBQueryPathInformationResponse_Parameters()
                respData = infoRecord
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryFsInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)
        errorCode = 0
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            data = queryFsInformation(connData['ConnectedShares'][recvPacket['Tid']]['path'], '', struct.unpack('<H',parameters)[0])

        smbServer.setConnectionData(connId, connData)

        return '','', data, errorCode

    @staticmethod
    def findNext2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        findNext2Parameters = smb.SMBFindNext2_Parameters(flags = recvPacket['Flags2'], data = parameters)

        sid = findNext2Parameters['SID']
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            if connData['SIDs'].has_key(sid):
                searchResult = connData['SIDs'][sid]
                respParameters = smb.SMBFindNext2Response_Parameters()
                endOfSearch = 1
                searchCount = 1
                totalData = 0
                for i in enumerate(searchResult):
                    data = i[1].getData()
                    lenData = len(data)
                    if (totalData+lenData) >= maxDataCount or (i[0]+1) >= findNext2Parameters['SearchCount']:
                        # We gotta stop here and continue on a find_next2
                        endOfSearch = 0
                        connData['SIDs'][sid] = searchResult[i[0]:]
                        respParameters['LastNameOffset'] = totalData
                        break
                    else:
                        searchCount +=1
                        respData += data
                        totalData += lenData

                # Have we reached the end of the search or still stuff to send?
                if endOfSearch > 0:
                    # Let's remove the SID from our ConnData
                    del(connData['SIDs'][sid])

                respParameters['EndOfSearch'] = endOfSearch
                respParameters['SearchCount'] = searchCount
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def findFirst2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        findFirst2Parameters = smb.SMBFindFirst2_Parameters( recvPacket['Flags2'], data = parameters)

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']

            searchResult, searchCount, errorCode = findFirst2(path,
                          decodeSMBString( recvPacket['Flags2'], findFirst2Parameters['FileName'] ),
                          findFirst2Parameters['InformationLevel'],
                          findFirst2Parameters['SearchAttributes'] )

            respParameters = smb.SMBFindFirst2Response_Parameters()
            endOfSearch = 1
            sid = 0x80 # default SID
            searchCount = 0
            totalData = 0
            for i in enumerate(searchResult):
                #i[1].dump()
                data = i[1].getData()
                lenData = len(data)
                if (totalData+lenData) >= maxDataCount or (i[0]+1) > findFirst2Parameters['SearchCount']:
                    # We gotta stop here and continue on a find_next2
                    endOfSearch = 0
                    # Simple way to generate a fid
                    if len(connData['SIDs']) == 0:
                       sid = 1
                    else:
                       sid = connData['SIDs'].keys()[-1] + 1
                    # Store the remaining search results in the ConnData SID
                    connData['SIDs'][sid] = searchResult[i[0]:]
                    respParameters['LastNameOffset'] = totalData
                    break
                else:
                    searchCount +=1
                    respData += data

                    padLen = (8-(lenData % 8)) %8
                    respData += '\xaa'*padLen
                    totalData += lenData + padLen

            respParameters['SID'] = sid
            respParameters['EndOfSearch'] = endOfSearch
            respParameters['SearchCount'] = searchCount
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

# Here we implement the commands handlers
class SMBCommands:

    @staticmethod
    def smbTransaction(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        transParameters= smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if transParameters['ParameterCount'] != transParameters['TotalParameterCount']:
            # TODO: Handle partial parameters
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            transData = smb.SMBTransaction_SData(flags = recvPacket['Flags2'])
            # Standard says servers shouldn't trust Parameters and Data comes
            # in order, so we have to parse the offsets, ugly

            paramCount = transParameters['ParameterCount']
            transData['Trans_ParametersLength'] = paramCount
            dataCount = transParameters['DataCount']
            transData['Trans_DataLength'] = dataCount
            transData.fromString(SMBCommand['Data'])
            if transParameters['ParameterOffset'] > 0:
                paramOffset = transParameters['ParameterOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                transData['Trans_Parameters'] = ''

            if transParameters['DataOffset'] > 0:
                dataOffset = transParameters['DataOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                transData['Trans_Data'] = ''

            # Call the handler for this TRANSACTION
            if transParameters['SetupCount'] == 0:
                # No subcommand, let's play with the Name
                command = decodeSMBString(recvPacket['Flags2'],transData['Name'])
            else:
                command = struct.unpack('<H', transParameters['Setup'][:2])[0]

            if transCommands.has_key(command):
               # Call the TRANS subcommand
               setup = ''
               parameters = ''
               data = ''
               try:
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer,
                                recvPacket,
                                transData['Trans_Parameters'],
                                transData['Trans_Data'],
                                transParameters['MaxDataCount'])
               except Exception, e:
                   #print 'Transaction: %s' % e,e
                   smbServer.log('Transaction: (%r,%s)' % (command, e), logging.ERROR)
                   errorCode = STATUS_ACCESS_DENIED
                   #raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0:
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBTransactionResponse_Parameters()
                       respData       = smb.SMBTransaction2Response_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement

                       # TODO: Do the same for parameters
                       if len(data) >  transParameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           LOG.debug("Lowering answer from %d to %d" % (len(data),transParameters['MaxDataCount']) )
                           respParameters['DataCount'] = transParameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if len(parameters) > 0:
                           #padLen = 4 - (55 + len(setup)) % 4
                           padLen = (4 - (55 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 55 + len(setup) + padLen
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if len(data) > 0:
                           #pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['Trans_Data']       = data[:respParameters['DataCount']]
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               smbServer.log("Unsupported Transact command %r" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbNTTransact(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        NTTransParameters= smb.SMBNTTransaction_Parameters(SMBCommand['Parameters'])
        # Do the stuff
        if NTTransParameters['ParameterCount'] != NTTransParameters['TotalParameterCount']:
            # TODO: Handle partial parameters
            raise Exception("Unsupported partial parameters in NTTrans!")
        else:
            NTTransData = smb.SMBNTTransaction_Data()
            # Standard says servers shouldn't trust Parameters and Data comes
            # in order, so we have to parse the offsets, ugly

            paramCount = NTTransParameters['ParameterCount']
            NTTransData['NT_Trans_ParametersLength'] = paramCount
            dataCount = NTTransParameters['DataCount']
            NTTransData['NT_Trans_DataLength'] = dataCount

            if NTTransParameters['ParameterOffset'] > 0:
                paramOffset = NTTransParameters['ParameterOffset'] - 73 - NTTransParameters['SetupLength']
                NTTransData['NT_Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                NTTransData['NT_Trans_Parameters'] = ''

            if NTTransParameters['DataOffset'] > 0:
                dataOffset = NTTransParameters['DataOffset'] - 73 - NTTransParameters['SetupLength']
                NTTransData['NT_Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                NTTransData['NT_Trans_Data'] = ''

            # Call the handler for this TRANSACTION
            command = NTTransParameters['Function']
            if transCommands.has_key(command):
               # Call the NT TRANS subcommand
               setup = ''
               parameters = ''
               data = ''
               try:
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer,
                                recvPacket,
                                NTTransData['NT_Trans_Parameters'],
                                NTTransData['NT_Trans_Data'],
                                NTTransParameters['MaxDataCount'])
               except Exception, e:
                   smbServer.log('NTTransaction: (0x%x,%s)' % (command, e), logging.ERROR)
                   errorCode = STATUS_ACCESS_DENIED
                   #raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
                   if errorCode == STATUS_SUCCESS:
                       errorCode = STATUS_ACCESS_DENIED
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0:
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBNTTransactionResponse_Parameters()
                       respData       = smb.SMBNTTransactionResponse_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement
                       # TODO: Do the same for parameters
                       if len(data) >  NTTransParameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           LOG.debug("Lowering answer from %d to %d" % (len(data),NTTransParameters['MaxDataCount']) )
                           respParameters['DataCount'] = NTTransParameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['NT_Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if len(parameters) > 0:
                           #padLen = 4 - (71 + len(setup)) % 4
                           padLen = (4 - (73 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 73 + len(setup) + padLen
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if len(data) > 0:
                           #pad2Len = 4 - (71 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (73 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 73 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['NT_Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['NT_Trans_Data']       = data[:respParameters['DataCount']]
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               #smbServer.log("Unsupported NTTransact command 0x%x" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbTransaction2(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        trans2Parameters= smb.SMBTransaction2_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if trans2Parameters['ParameterCount'] != trans2Parameters['TotalParameterCount']:
            # TODO: Handle partial parameters
            #print "Unsupported partial parameters in TRANSACT2!"
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            trans2Data = smb.SMBTransaction2_Data()
            # Standard says servers shouldn't trust Parameters and Data comes
            # in order, so we have to parse the offsets, ugly

            paramCount = trans2Parameters['ParameterCount']
            trans2Data['Trans_ParametersLength'] = paramCount
            dataCount = trans2Parameters['DataCount']
            trans2Data['Trans_DataLength'] = dataCount

            if trans2Parameters['ParameterOffset'] > 0:
                paramOffset = trans2Parameters['ParameterOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                trans2Data['Trans_Parameters'] = ''

            if trans2Parameters['DataOffset'] > 0:
                dataOffset = trans2Parameters['DataOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                trans2Data['Trans_Data'] = ''

            # Call the handler for this TRANSACTION
            command = struct.unpack('<H', trans2Parameters['Setup'])[0]
            if transCommands.has_key(command):
               # Call the TRANS2 subcommand
               try:
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer,
                                recvPacket,
                                trans2Data['Trans_Parameters'],
                                trans2Data['Trans_Data'],
                                trans2Parameters['MaxDataCount'])
               except Exception, e:
                   smbServer.log('Transaction2: (0x%x,%s)' % (command, e), logging.ERROR)
                   #import traceback
                   #traceback.print_exc()
                   raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0:
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBTransaction2Response_Parameters()
                       respData       = smb.SMBTransaction2Response_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement
                       # TODO: Do the same for parameters
                       if len(data) >  trans2Parameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           LOG.debug("Lowering answer from %d to %d" % (len(data),trans2Parameters['MaxDataCount']) )
                           respParameters['DataCount'] = trans2Parameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if len(parameters) > 0:
                           #padLen = 4 - (55 + len(setup)) % 4
                           padLen = (4 - (55 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 55 + len(setup) + padLen
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if len(data) > 0:
                           #pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['Trans_Data']       = data[:respParameters['DataCount']]
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               smbServer.log("Unsupported Transact/2 command 0x%x" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComLockingAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_LOCKING_ANDX)
        respParameters        = ''
        respData              = ''

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbComClose(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)
        respParameters        = ''
        respData              = ''

        comClose =  smb.SMBClose_Parameters(SMBCommand['Parameters'])

        if connData['OpenedFiles'].has_key(comClose['FID']):
             errorCode = STATUS_SUCCESS
             fileHandle = connData['OpenedFiles'][comClose['FID']]['FileHandle']
             try:
                 if fileHandle == PIPE_FILE_DESCRIPTOR:
                     connData['OpenedFiles'][comClose['FID']]['Socket'].close()
                 elif fileHandle != VOID_FILE_DESCRIPTOR:
                     os.close(fileHandle)
             except Exception, e:
                 smbServer.log("comClose %s" % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
             else:
                 # Check if the file was marked for removal
                 if connData['OpenedFiles'][comClose['FID']]['DeleteOnClose'] is True:
                     try:
                         os.remove(connData['OpenedFiles'][comClose['FID']]['FileName'])
                     except Exception, e:
                         smbServer.log("comClose %s" % e, logging.ERROR)
                         errorCode = STATUS_ACCESS_DENIED
                 del(connData['OpenedFiles'][comClose['FID']])
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComWrite(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_WRITE)
        respParameters        = smb.SMBWriteResponse_Parameters()
        respData              = ''

        comWriteParameters =  smb.SMBWrite_Parameters(SMBCommand['Parameters'])
        comWriteData = smb.SMBWrite_Data(SMBCommand['Data'])

        if connData['OpenedFiles'].has_key(comWriteParameters['Fid']):
             fileHandle = connData['OpenedFiles'][comWriteParameters['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     # If we're trying to write past the file end we just skip the write call (Vista does this)
                     if os.lseek(fileHandle, 0, 2) >= comWriteParameters['Offset']:
                         os.lseek(fileHandle,comWriteParameters['Offset'],0)
                         os.write(fileHandle,comWriteData['Data'])
                 else:
                     sock = connData['OpenedFiles'][comWriteParameters['Fid']]['Socket']
                     sock.send(comWriteData['Data'])
                 respParameters['Count']    = comWriteParameters['Count']
             except Exception, e:
                 smbServer.log('smbComWrite: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComFlush(connId, smbServer, SMBCommand,recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_FLUSH)
        respParameters        = ''
        respData              = ''

        comFlush =  smb.SMBFlush_Parameters(SMBCommand['Parameters'])

        if connData['OpenedFiles'].has_key(comFlush['FID']):
             errorCode = STATUS_SUCCESS
             fileHandle = connData['OpenedFiles'][comFlush['FID']]['FileHandle']
             try:
                 os.fsync(fileHandle)
             except Exception, e:
                 smbServer.log("comFlush %s" % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbComCreateDirectory(connId, smbServer, SMBCommand,recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_CREATE_DIRECTORY)
        respParameters        = ''
        respData              = ''

        comCreateDirectoryData=  smb.SMBCreateDirectory_Data(flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],comCreateDirectoryData['DirectoryName']).replace('\\','/'))
             if len(fileName) > 0:
                if fileName[0] == '/' or fileName[0] == '\\':
                    # strip leading '/'
                    fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName):
                errorCode = STATUS_OBJECT_NAME_COLLISION

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.mkdir(pathName)
                 except Exception, e:
                     smbServer.log("smbComCreateDirectory: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComRename(connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_RENAME)
        respParameters        = ''
        respData              = ''

        comRenameData      =  smb.SMBRename_Data(flags = recvPacket['Flags2'], data = SMBCommand['Data'])
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             oldFileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],comRenameData['OldFileName']).replace('\\','/'))
             newFileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],comRenameData['NewFileName']).replace('\\','/'))
             if len(oldFileName) > 0 and (oldFileName[0] == '/' or oldFileName[0] == '\\'):
                # strip leading '/'
                oldFileName = oldFileName[1:]
             oldPathName = os.path.join(path,oldFileName)
             if len(newFileName) > 0 and (newFileName[0] == '/' or newFileName[0] == '\\'):
                # strip leading '/'
                newFileName = newFileName[1:]
             newPathName = os.path.join(path,newFileName)

             if os.path.exists(oldPathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.rename(oldPathName,newPathName)
                 except OSError, e:
                     smbServer.log("smbComRename: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComDelete(connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_DELETE)
        respParameters        = ''
        respData              = ''

        comDeleteData         =  smb.SMBDelete_Data(flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],comDeleteData['FileName']).replace('\\','/'))
             if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.remove(pathName)
                 except OSError, e:
                     smbServer.log("smbComDelete: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbComDeleteDirectory(connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_DELETE_DIRECTORY)
        respParameters        = ''
        respData              = ''

        comDeleteDirectoryData=  smb.SMBDeleteDirectory_Data(flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],comDeleteDirectoryData['DirectoryName']).replace('\\','/'))
             if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.rmdir(pathName)
                 except OSError, e:
                     smbServer.log("smbComDeleteDirectory: %s" % e,logging.ERROR)
                     if e.errno == errno.ENOTEMPTY:
                         errorCode = STATUS_DIRECTORY_NOT_EMPTY
                     else:
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    @staticmethod
    def smbComWriteAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
        respParameters        = smb.SMBWriteAndXResponse_Parameters()
        respData              = ''

        if SMBCommand['WordCount'] == 0x0C:
            writeAndX =  smb.SMBWriteAndX_Parameters_Short(SMBCommand['Parameters'])
            writeAndXData = smb.SMBWriteAndX_Data_Short()
        else:
            writeAndX =  smb.SMBWriteAndX_Parameters(SMBCommand['Parameters'])
            writeAndXData = smb.SMBWriteAndX_Data()
        writeAndXData['DataLength'] = writeAndX['DataLength']
        writeAndXData['DataOffset'] = writeAndX['DataOffset']
        writeAndXData.fromString(SMBCommand['Data'])


        if connData['OpenedFiles'].has_key(writeAndX['Fid']):
             fileHandle = connData['OpenedFiles'][writeAndX['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = writeAndX['Offset']
                     if writeAndX.fields.has_key('HighOffset'):
                         offset += (writeAndX['HighOffset'] << 32)
                     # If we're trying to write past the file end we just skip the write call (Vista does this)
                     if os.lseek(fileHandle, 0, 2) >= offset:
                         os.lseek(fileHandle,offset,0)
                         os.write(fileHandle,writeAndXData['Data'])
                 else:
                     sock = connData['OpenedFiles'][writeAndX['Fid']]['Socket']
                     sock.send(writeAndXData['Data'])

                 respParameters['Count']    = writeAndX['DataLength']
                 respParameters['Available']= 0xff
             except Exception, e:
                 smbServer.log('smbComWriteAndx: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComRead(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_READ)
        respParameters        = smb.SMBReadResponse_Parameters()
        respData              = smb.SMBReadResponse_Data()

        comReadParameters =  smb.SMBRead_Parameters(SMBCommand['Parameters'])

        if connData['OpenedFiles'].has_key(comReadParameters['Fid']):
             fileHandle = connData['OpenedFiles'][comReadParameters['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     os.lseek(fileHandle,comReadParameters['Offset'],0)
                     content = os.read(fileHandle,comReadParameters['Count'])
                 else:
                     sock = connData['OpenedFiles'][comReadParameters['Fid']]['Socket']
                     content = sock.recv(comReadParameters['Count'])
                 respParameters['Count']    = len(content)
                 respData['DataLength']     = len(content)
                 respData['Data']           = content
             except Exception, e:
                 smbServer.log('smbComRead: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComReadAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
        respParameters        = smb.SMBReadAndXResponse_Parameters()
        respData              = ''

        if SMBCommand['WordCount'] == 0x0A:
            readAndX =  smb.SMBReadAndX_Parameters2(SMBCommand['Parameters'])
        else:
            readAndX =  smb.SMBReadAndX_Parameters(SMBCommand['Parameters'])

        if connData['OpenedFiles'].has_key(readAndX['Fid']):
             fileHandle = connData['OpenedFiles'][readAndX['Fid']]['FileHandle']
             errorCode = 0
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = readAndX['Offset']
                     if readAndX.fields.has_key('HighOffset'):
                         offset += (readAndX['HighOffset'] << 32)
                     os.lseek(fileHandle,offset,0)
                     content = os.read(fileHandle,readAndX['MaxCount'])
                 else:
                     sock = connData['OpenedFiles'][readAndX['Fid']]['Socket']
                     content = sock.recv(readAndX['MaxCount'])
                 respParameters['Remaining']    = 0xffff
                 respParameters['DataCount']    = len(content)
                 respParameters['DataOffset']   = 59
                 respParameters['DataCount_Hi'] = 0
                 respData = content
             except Exception, e:
                 smbServer.log('smbComReadAndX: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbQueryInformation(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION)
        respParameters = smb.SMBQueryInformationResponse_Parameters()
        respData       = ''

        queryInformation= smb.SMBQueryInformation_Data(flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            fileSize, lastWriteTime, fileAttributes = queryFsInformation(
                connData['ConnectedShares'][recvPacket['Tid']]['path'],
                decodeSMBString(recvPacket['Flags2'],queryInformation['FileName']))

            respParameters['FileSize']       = fileSize
            respParameters['LastWriteTime']  = lastWriteTime
            respParameters['FileAttributes'] = fileAttributes
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID
            respParameters  = ''
            respData        = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbQueryInformationDisk(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION_DISK)
        respParameters = smb.SMBQueryInformationDiskResponse_Parameters()
        respData       = ''

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            totalUnits, freeUnits = queryDiskInformation(
                        connData['ConnectedShares'][recvPacket['Tid']]['path'])

            respParameters['TotalUnits']    = totalUnits
            respParameters['BlocksPerUnit'] = 1
            respParameters['BlockSize']     = 1
            respParameters['FreeUnits']     = freeUnits
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            respData  = ''
            respParameters = ''
            errorCode = STATUS_SMB_BAD_TID


        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComEcho(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        respParameters = smb.SMBEchoResponse_Parameters()
        respData       = smb.SMBEchoResponse_Data()

        echoData       = smb.SMBEcho_Data(SMBCommand['Data'])

        respParameters['SequenceNumber'] = 1
        respData['Data']                 = echoData['Data']

        respSMBCommand['Parameters']     = respParameters
        respSMBCommand['Data']           = respData

        errorCode = STATUS_SUCCESS
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComTreeDisconnect(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_TREE_DISCONNECT)

        # Check if the Tid matches the Tid trying to disconnect
        respParameters = ''
        respData = ''

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            smbServer.log("Disconnecting Share(%d:%s)" % (recvPacket['Tid'],connData['ConnectedShares'][recvPacket['Tid']]['shareName']))
            del(connData['ConnectedShares'][recvPacket['Tid']])
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComLogOffAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_LOGOFF_ANDX)

        # Check if the Uid matches the user trying to logoff
        respParameters = ''
        respData = ''
        if recvPacket['Uid'] != connData['Uid']:
            # STATUS_SMB_BAD_UID
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters']   = respParameters
        respSMBCommand['Data']         = respData
        connData['Uid'] = 0

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComQueryInformation2(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION2)
        respParameters        = smb.SMBQueryInformation2Response_Parameters()
        respData              = ''

        queryInformation2 = smb.SMBQueryInformation2_Parameters(SMBCommand['Parameters'])
        errorCode = 0xFF
        if connData['OpenedFiles'].has_key(queryInformation2['Fid']):
             errorCode = STATUS_SUCCESS
             pathName = connData['OpenedFiles'][queryInformation2['Fid']]['FileName']
             try:
                 (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
                 respParameters['CreateDate']         = getSMBDate(ctime)
                 respParameters['CreationTime']       = getSMBTime(ctime)
                 respParameters['LastAccessDate']     = getSMBDate(atime)
                 respParameters['LastAccessTime']     = getSMBTime(atime)
                 respParameters['LastWriteDate']      = getSMBDate(mtime)
                 respParameters['LastWriteTime']      = getSMBTime(mtime)
                 respParameters['FileDataSize']       = size
                 respParameters['FileAllocationSize'] = size
                 attribs = 0
                 if os.path.isdir(pathName):
                     attribs = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                 if os.path.isfile(pathName):
                     attribs = smb.SMB_FILE_ATTRIBUTE_NORMAL
                 respParameters['FileAttributes'] = attribs
             except Exception, e:
                 smbServer.log('smbComQueryInformation2 %s' % e,logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket):
        # TODO: Fully implement this
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
        respParameters        = smb.SMBNtCreateAndXResponse_Parameters()
        respData              = ''

        ntCreateAndXParameters = smb.SMBNtCreateAndX_Parameters(SMBCommand['Parameters'])
        ntCreateAndXData       = smb.SMBNtCreateAndX_Data( flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        #if ntCreateAndXParameters['CreateFlags'] & 0x10:  # NT_CREATE_REQUEST_EXTENDED_RESPONSE
        #    respParameters        = smb.SMBNtCreateAndXExtendedResponse_Parameters()
        #    respParameters['VolumeGUID'] = '\x00'

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             # If we have a rootFid, the path is relative to that fid
             errorCode = STATUS_SUCCESS
             if ntCreateAndXParameters['RootFid'] > 0:
                 path = connData['OpenedFiles'][ntCreateAndXParameters['RootFid']]['FileName']
                 LOG.debug("RootFid present %s!" % path)
             else:
                 if connData['ConnectedShares'][recvPacket['Tid']].has_key('path'):
                     path = connData['ConnectedShares'][recvPacket['Tid']]['path']
                 else:
                     path = 'NONE'
                     errorCode = STATUS_ACCESS_DENIED

             deleteOnClose = False

             fileName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],ntCreateAndXData['FileName']).replace('\\','/'))
             if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             createDisposition = ntCreateAndXParameters['Disposition']
             mode = 0

             if createDisposition == smb.FILE_SUPERSEDE:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_OVERWRITE_IF == smb.FILE_OVERWRITE_IF:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_OVERWRITE == smb.FILE_OVERWRITE:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC
                 else:
                     errorCode = STATUS_NO_SUCH_FILE
             elif createDisposition & smb.FILE_OPEN_IF == smb.FILE_OPEN_IF:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC
                 else:
                     mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_CREATE == smb.FILE_CREATE:
                 if os.path.exists(pathName) is True:
                     errorCode = STATUS_OBJECT_NAME_COLLISION
                 else:
                     mode |= os.O_CREAT
             elif createDisposition & smb.FILE_OPEN == smb.FILE_OPEN:
                 if os.path.exists(pathName) is not True and smbServer.getRegisteredNamedPipes().has_key(unicode(pathName)) is not True:
                     errorCode = STATUS_NO_SUCH_FILE

             if errorCode == STATUS_SUCCESS:
                 desiredAccess = ntCreateAndXParameters['AccessMask']
                 if (desiredAccess & smb.FILE_READ_DATA) or (desiredAccess & smb.GENERIC_READ):
                     mode |= os.O_RDONLY
                 if (desiredAccess & smb.FILE_WRITE_DATA) or (desiredAccess & smb.GENERIC_WRITE):
                     if (desiredAccess & smb.FILE_READ_DATA) or (desiredAccess & smb.GENERIC_READ):
                         mode |= os.O_RDWR #| os.O_APPEND
                     else:
                         mode |= os.O_WRONLY #| os.O_APPEND
                 if desiredAccess & smb.GENERIC_ALL:
                     mode |= os.O_RDWR #| os.O_APPEND

                 createOptions =  ntCreateAndXParameters['CreateOptions']
                 if mode & os.O_CREAT == os.O_CREAT:
                     if createOptions & smb.FILE_DIRECTORY_FILE == smb.FILE_DIRECTORY_FILE:
                         try:
                             # Let's create the directory
                             os.mkdir(pathName)
                             mode = os.O_RDONLY
                         except Exception, e:
                             smbServer.log("NTCreateAndX: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                             errorCode = STATUS_ACCESS_DENIED
                 if createOptions & smb.FILE_NON_DIRECTORY_FILE == smb.FILE_NON_DIRECTORY_FILE:
                     # If the file being opened is a directory, the server MUST fail the request with
                     # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                     # response.
                     if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                 if createOptions & smb.FILE_DELETE_ON_CLOSE == smb.FILE_DELETE_ON_CLOSE:
                     deleteOnClose = True

                 if errorCode == STATUS_SUCCESS:
                     try:
                         if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                         else:
                            if sys.platform == 'win32':
                               mode |= os.O_BINARY
                            if smbServer.getRegisteredNamedPipes().has_key(unicode(pathName)):
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[unicode(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                     except Exception, e:
                         smbServer.log("NTCreateAndX: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                         #print e
                         fid = 0
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            if len(connData['OpenedFiles']) == 0:
               fakefid = 1
            else:
               fakefid = connData['OpenedFiles'].keys()[-1] + 1
            respParameters['Fid'] = fakefid
            respParameters['CreateAction'] = createDisposition
            if fid == PIPE_FILE_DESCRIPTOR:
                respParameters['FileAttributes'] = 0x80
                respParameters['IsDirectory'] = 0
                respParameters['CreateTime']     = 0
                respParameters['LastAccessTime'] = 0
                respParameters['LastWriteTime']  = 0
                respParameters['LastChangeTime'] = 0
                respParameters['AllocationSize'] = 4096
                respParameters['EndOfFile']      = 0
                respParameters['FileType']       = 2
                respParameters['IPCState']       = 0x5ff
            else:
                if os.path.isdir(pathName):
                    respParameters['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                    respParameters['IsDirectory'] = 1
                else:
                    respParameters['IsDirectory'] = 0
                    respParameters['FileAttributes'] = ntCreateAndXParameters['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation('',pathName,level= smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respParameters['CreateTime']     = respInfo['CreationTime']
                    respParameters['LastAccessTime'] = respInfo['LastAccessTime']
                    respParameters['LastWriteTime']  = respInfo['LastWriteTime']
                    respParameters['LastChangeTime'] = respInfo['LastChangeTime']
                    respParameters['FileAttributes'] = respInfo['ExtFileAttributes']
                    respParameters['AllocationSize'] = respInfo['AllocationSize']
                    respParameters['EndOfFile']      = respInfo['EndOfFile']
                else:
                    respParameters = ''
                    respData       = ''

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose']  = deleteOnClose
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComOpenAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_OPEN_ANDX)
        respParameters        = smb.SMBOpenAndXResponse_Parameters()
        respData              = ''

        openAndXParameters = smb.SMBOpenAndX_Parameters(SMBCommand['Parameters'])
        openAndXData       = smb.SMBOpenAndX_Data( flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             openedFile, mode, pathName, errorCode = openFile(path,
                     decodeSMBString(recvPacket['Flags2'],openAndXData['FileName']),
                     openAndXParameters['DesiredAccess'],
                     openAndXParameters['FileAttributes'],
                     openAndXParameters['OpenMode'])
        else:
           errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fid = len(connData['OpenedFiles']) + 1
            if len(connData['OpenedFiles']) == 0:
               fid = 1
            else:
               fid = connData['OpenedFiles'].keys()[-1] + 1
            respParameters['Fid'] = fid
            if mode & os.O_CREAT:
                # File did not exist and was created
                respParameters['Action'] = 0x2
            elif mode & os.O_RDONLY:
                # File existed and was opened
                respParameters['Action'] = 0x1
            elif mode & os.O_APPEND:
                # File existed and was opened
                respParameters['Action'] = 0x1
            else:
                # File existed and was truncated
                respParameters['Action'] = 0x3

            # Let's store the fid for the connection
            #smbServer.log('Opening file %s' % pathName)
            connData['OpenedFiles'][fid] = {}
            connData['OpenedFiles'][fid]['FileHandle'] = openedFile
            connData['OpenedFiles'][fid]['FileName'] = pathName
            connData['OpenedFiles'][fid]['DeleteOnClose']  = False
        else:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | recvPacket['Flags2'] & smb.SMB.FLAGS2_UNICODE

        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Pid'] = connData['Pid']

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX)
        respParameters        = smb.SMBTreeConnectAndXResponse_Parameters()
        respData              = smb.SMBTreeConnectAndXResponse_Data()

        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

        if treeConnectAndXParameters['Flags'] & 0x8:
            respParameters        = smb.SMBTreeConnectAndXExtendedResponse_Parameters()

        treeConnectAndXData                    = smb.SMBTreeConnectAndX_Data( flags = recvPacket['Flags2'] )
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        UNCOrShare = decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Path'])

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        share = searchShare(connId, path, smbServer)
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
               tid = 1
            else:
               tid = connData['ConnectedShares'].keys()[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            resp['Tid'] = tid
            #smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("TreeConnectAndX not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            resp['ErrorCode']   = errorCode >> 16
            resp['ErrorClass']  = errorCode & 0xff
        ##
        respParameters['OptionalSupport'] = smb.SMB.SMB_SUPPORT_SEARCH_BITS

        if path == 'IPC$':
            respData['Service']               = 'IPC'
        else:
            respData['Service']               = path
        respData['PadLen']                = 0
        respData['NativeFileSystem']      = encodeSMBString(recvPacket['Flags2'], 'NTFS' )

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode

    @staticmethod
    def smbComSessionSetupAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        # From [MS-SMB]
        # When extended security is being used (see section 3.2.4.2.4), the
        # request MUST take the following form
        # [..]
        # WordCount (1 byte): The value of this field MUST be 0x0C.
        if SMBCommand['WordCount'] == 12:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = smb.SMBSessionSetupAndX_Extended_Response_Data(flags = recvPacket['Flags2'])
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            rawNTLM = False
            if struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] == ASN1_AID:
               # NEGOTIATE packet
               blob =  SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']
               if len(blob['MechTypes'][0]) > 0:
                   # Is this GSSAPI NTLM or something else we don't support?
                   mechType = blob['MechTypes'][0]
                   if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                       # Nope, do we know it?
                       if MechTypes.has_key(mechType):
                           mechStr = MechTypes[mechType]
                       else:
                           mechStr = hexlify(mechType)
                       smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                       # We don't know the token, we answer back again saying
                       # we just support NTLM.
                       # ToDo: Build this into a SPNEGO_NegTokenResp()
                       respToken = '\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                       respParameters['SecurityBlobLength'] = len(respToken)
                       respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
                       respData['SecurityBlob']       = respToken
                       respData['NativeOS']     = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
                       respData['NativeLanMan'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData
                       return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED

            elif struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] == ASN1_SUPPORTED_MECH:
               # AUTH packet
               blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # No GSSAPI stuff, raw NTLMSSP
               rawNTLM = True
               token = sessionSetupData['SecurityBlob']

            # Here we only handle NTLMSSP, depending on what stage of the
            # authentication we are, we act on it
            messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage
                # Let's build the answer flags
                # TODO: Parse all the flags. With this we're leaving some clients out

                ansFlags = 0

                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
                   ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
                   ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
                   ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                   ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                   ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
                if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
                   ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

                # Generate the AV_PAIRS
                av_pairs = ntlm.AV_PAIRS()
                # TODO: Put the proper data from SMBSERVER config
                av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )

                challengeMessage = ntlm.NTLMAuthChallenge()
                challengeMessage['flags']            = ansFlags
                challengeMessage['domain_len']       = len(smbServer.getServerDomain().encode('utf-16le'))
                challengeMessage['domain_max_len']   = challengeMessage['domain_len']
                challengeMessage['domain_offset']    = 40 + 16
                challengeMessage['challenge']        = smbServer.getSMBChallenge()
                challengeMessage['domain_name']      = smbServer.getServerDomain().encode('utf-16le')
                challengeMessage['TargetInfoFields_len']     = len(av_pairs)
                challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
                challengeMessage['TargetInfoFields'] = av_pairs
                challengeMessage['TargetInfoFields_offset']  = 40 + 16 + len(challengeMessage['domain_name'])
                challengeMessage['Version']          = '\xff'*8
                challengeMessage['VersionLen']       = 8

                if rawNTLM is False:
                    respToken = SPNEGO_NegTokenResp()
                    # accept-incomplete. We want more data
                    respToken['NegResult'] = '\x01'
                    respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                    respToken['ResponseToken'] = challengeMessage.getData()
                else:
                    respToken = challengeMessage

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                # Let's set up an UID for this connection and store it
                # in the connection's data
                # Picking a fixed value
                # TODO: Manage more UIDs for the same session
                connData['Uid'] = 10
                # Let's store it in the connection data
                connData['CHALLENGE_MESSAGE'] = challengeMessage

            elif messageType == 0x02:
                # CHALLENGE_MESSAGE
                raise Exception('Challenge Message raise, not implemented!')
            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (authenticateMessage['domain_name'], authenticateMessage['user_name'], authenticateMessage['host_name']))
                # TODO: Check the credentials! Now granting permissions

                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                errorCode = STATUS_SUCCESS
                smbServer.log('User %s\\%s authenticated successfully' % (authenticateMessage['user_name'], authenticateMessage['host_name']))
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
                try:
                    jtr_dump_path = smbServer.getJTRdumpPath()
                    ntlm_hash_data = outputToJohnFormat( connData['CHALLENGE_MESSAGE']['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'], authenticateMessage['lanman'], authenticateMessage['ntlm'] )
                    smbServer.log(ntlm_hash_data['hash_string'])
                    if jtr_dump_path is not '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], jtr_dump_path)
                except:
                    smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)
            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)
            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData       = smb.SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = STATUS_SUCCESS
            connData['Uid'] = 10
            respParameters['Action'] = 0
            smbServer.log('User %s\\%s authenticated successfully (basic)' % (sessionSetupData['PrimaryDomain'], sessionSetupData['Account']))
            try:
                jtr_dump_path = smbServer.getJTRdumpPath()
                ntlm_hash_data = outputToJohnFormat( '', sessionSetupData['Account'], sessionSetupData['PrimaryDomain'], sessionSetupData['AnsiPwd'], sessionSetupData['UnicodePwd'] )
                smbServer.log(ntlm_hash_data['hash_string'])
                if jtr_dump_path is not '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], jtr_dump_path)
            except:
                smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)

        respData['NativeOS']     = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
        respData['NativeLanMan'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        #os.setregid(65534,65534)
        #os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComNegotiate(connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        connData['Pid'] = recvPacket['Pid']

        SMBCommand = smb.SMBCommand(recvPacket['Data'][0])
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Pid'] = connData['Pid']
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']

        # TODO: We support more dialects, and parse them accordingly
        dialects = SMBCommand['Data'].split('\x02')
        try:
           index = dialects.index('NT LM 0.12\x00') - 1
           # Let's fill the data for NTLM
           if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
                    resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_UNICODE
                    #resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
                    _dialects_data = smb.SMBExtended_Security_Data()
                    _dialects_data['ServerGUID'] = 'A'*16
                    blob = SPNEGO_NegTokenInit()
                    blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                    _dialects_data['SecurityBlob'] = blob.getData()

                    _dialects_parameters = smb.SMBExtended_Security_Parameters()
                    _dialects_parameters['Capabilities']    = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS | smb.SMB.CAP_UNICODE
                    _dialects_parameters['ChallengeLength'] = 0

           else:
                    resp['Flags2'] = smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_UNICODE
                    _dialects_parameters = smb.SMBNTLMDialect_Parameters()
                    _dialects_data= smb.SMBNTLMDialect_Data()
                    _dialects_data['Payload'] = ''
                    if connData.has_key('EncryptionKey'):
                        _dialects_data['Challenge'] = connData['EncryptionKey']
                        _dialects_parameters['ChallengeLength'] = len(str(_dialects_data))
                    else:
                        # TODO: Handle random challenges, now one that can be used with rainbow tables
                        _dialects_data['Challenge'] = '\x11\x22\x33\x44\x55\x66\x77\x88'
                        _dialects_parameters['ChallengeLength'] = 8
                    _dialects_parameters['Capabilities']    = smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS

           # Let's see if we need to support RPC_REMOTE_APIS
           config = smbServer.getServerConfig()
           if config.has_option('global','rpc_apis'):
               if config.getboolean('global', 'rpc_apis') is True:
                  _dialects_parameters['Capabilities'] |= smb.SMB.CAP_RPC_REMOTE_APIS

           _dialects_parameters['DialectIndex']    = index
           _dialects_parameters['SecurityMode']    = smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
           _dialects_parameters['MaxMpxCount']     = 1
           _dialects_parameters['MaxNumberVcs']    = 1
           _dialects_parameters['MaxBufferSize']   = 64000
           _dialects_parameters['MaxRawSize']      = 65536
           _dialects_parameters['SessionKey']      = 0
           _dialects_parameters['LowDateTime']     = 0
           _dialects_parameters['HighDateTime']    = 0
           _dialects_parameters['ServerTimeZone']  = 0


           respSMBCommand['Data']           = _dialects_data
           respSMBCommand['Parameters']     = _dialects_parameters
           connData['_dialects_data']       = _dialects_data
           connData['_dialects_parameters'] = _dialects_parameters

        except Exception, e:
           # No NTLM throw an error
           smbServer.log('smbComNegotiate: %s' % e, logging.ERROR)
           respSMBCommand['Data'] = struct.pack('<H',0xffff)


        smbServer.setConnectionData(connId, connData)

        resp.addCommand(respSMBCommand)

        return None, [resp], STATUS_SUCCESS

    @staticmethod
    def default(connId, smbServer, SMBCommand, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'],logging.DEBUG)
        packet = smb.NewSMBPacket()
        packet['Flags1']  = smb.SMB.FLAGS1_REPLY
        packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS
        packet['Command'] = recvPacket['Command']
        packet['Pid']     = recvPacket['Pid']
        packet['Tid']     = recvPacket['Tid']
        packet['Mid']     = recvPacket['Mid']
        packet['Uid']     = recvPacket['Uid']
        packet['Data']    = '\x00\x00\x00'
        errorCode = STATUS_NOT_IMPLEMENTED
        packet['ErrorCode']   = errorCode >> 16
        packet['ErrorClass']  = errorCode & 0xff

        return None, [packet], errorCode

class SMB2Commands:
    @staticmethod
    def smb2Negotiate(connId, smbServer, recvPacket, isSMB1 = False):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = smb2.SMB2_NEGOTIATE
        respPacket['SessionID'] = 0
        if isSMB1 is False:
            respPacket['MessageID'] = recvPacket['MessageID']
        else:
            respPacket['MessageID'] = 0
        respPacket['TreeID']    = 0


        respSMBCommand = smb2.SMB2Negotiate_Response()

        respSMBCommand['SecurityMode'] = 1
        if isSMB1 is True:
            # Let's first parse the packet to see if the client supports SMB2
            SMBCommand = smb.SMBCommand(recvPacket['Data'][0])

            dialects = SMBCommand['Data'].split('\x02')
            if 'SMB 2.002\x00' in dialects or 'SMB 2.???\x00' in dialects:
                respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
            else:
                # Client does not support SMB2 fallbacking
                raise Exception('SMB2 not supported, fallbacking')
        else:
            respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
        respSMBCommand['ServerGuid'] = 'A'*16
        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaxTransactSize'] = 65536
        respSMBCommand['MaxReadSize'] = 65536
        respSMBCommand['MaxWriteSize'] = 65536
        respSMBCommand['SystemTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['ServerStartTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['SecurityBufferOffset'] = 0x80

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]

        respSMBCommand['Buffer'] = blob.getData()
        respSMBCommand['SecurityBufferLength'] = len(respSMBCommand['Buffer'])

        respPacket['Data']      = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], STATUS_SUCCESS

    @staticmethod
    def smb2SessionSetup(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respSMBCommand = smb2.SMB2SessionSetup_Response()

        sessionSetupData = smb2.SMB2SessionSetup(recvPacket['Data'])

        connData['Capabilities'] = sessionSetupData['Capabilities']

        securityBlob = sessionSetupData['Buffer']

        rawNTLM = False
        if struct.unpack('B',securityBlob[0])[0] == ASN1_AID:
           # NEGOTIATE packet
           blob =  SPNEGO_NegTokenInit(securityBlob)
           token = blob['MechToken']
           if len(blob['MechTypes'][0]) > 0:
               # Is this GSSAPI NTLM or something else we don't support?
               mechType = blob['MechTypes'][0]
               if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                   # Nope, do we know it?
                   if MechTypes.has_key(mechType):
                       mechStr = MechTypes[mechType]
                   else:
                       mechStr = hexlify(mechType)
                   smbServer.log("Unsupported MechType '%s'" % mechStr, logging.CRITICAL)
                   # We don't know the token, we answer back again saying
                   # we just support NTLM.
                   # ToDo: Build this into a SPNEGO_NegTokenResp()
                   respToken = '\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                   respSMBCommand['SecurityBufferOffset'] = 0x48
                   respSMBCommand['SecurityBufferLength'] = len(respToken)
                   respSMBCommand['Buffer'] = respToken

                   return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
        elif struct.unpack('B',securityBlob[0])[0] == ASN1_SUPPORTED_MECH:
           # AUTH packet
           blob = SPNEGO_NegTokenResp(securityBlob)
           token = blob['ResponseToken']
        else:
           # No GSSAPI stuff, raw NTLMSSP
           rawNTLM = True
           token = securityBlob

        # Here we only handle NTLMSSP, depending on what stage of the
        # authentication we are, we act on it
        messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

        if messageType == 0x01:
            # NEGOTIATE_MESSAGE
            negotiateMessage = ntlm.NTLMAuthNegotiate()
            negotiateMessage.fromString(token)
            # Let's store it in the connection data
            connData['NEGOTIATE_MESSAGE'] = negotiateMessage
            # Let's build the answer flags
            # TODO: Parse all the flags. With this we're leaving some clients out

            ansFlags = 0

            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
               ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
            if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
               ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

            # Generate the AV_PAIRS
            av_pairs = ntlm.AV_PAIRS()
            # TODO: Put the proper data from SMBSERVER config
            av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )

            challengeMessage = ntlm.NTLMAuthChallenge()
            challengeMessage['flags']            = ansFlags
            challengeMessage['domain_len']       = len(smbServer.getServerDomain().encode('utf-16le'))
            challengeMessage['domain_max_len']   = challengeMessage['domain_len']
            challengeMessage['domain_offset']    = 40 + 16
            challengeMessage['challenge']        = smbServer.getSMBChallenge()
            challengeMessage['domain_name']      = smbServer.getServerDomain().encode('utf-16le')
            challengeMessage['TargetInfoFields_len']     = len(av_pairs)
            challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
            challengeMessage['TargetInfoFields'] = av_pairs
            challengeMessage['TargetInfoFields_offset']  = 40 + 16 + len(challengeMessage['domain_name'])
            challengeMessage['Version']          = '\xff'*8
            challengeMessage['VersionLen']       = 8

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

            # Setting the packet to STATUS_MORE_PROCESSING
            errorCode = STATUS_MORE_PROCESSING_REQUIRED
            # Let's set up an UID for this connection and store it
            # in the connection's data
            # Picking a fixed value
            # TODO: Manage more UIDs for the same session
            connData['Uid'] = random.randint(1,0xffffffff)
            # Let's store it in the connection data
            connData['CHALLENGE_MESSAGE'] = challengeMessage

        elif messageType == 0x02:
            # CHALLENGE_MESSAGE
            raise Exception('Challenge Message raise, not implemented!')
        elif messageType == 0x03:
            # AUTHENTICATE_MESSAGE, here we deal with authentication
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)
            smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (authenticateMessage['domain_name'], authenticateMessage['user_name'], authenticateMessage['host_name']))
            # TODO: Check the credentials! Now granting permissions

            respToken = SPNEGO_NegTokenResp()
            # accept-completed
            respToken['NegResult'] = '\x00'

            # Status SUCCESS
            errorCode = STATUS_SUCCESS
            smbServer.log('User %s\\%s authenticated successfully' % (authenticateMessage['user_name'], authenticateMessage['host_name']))
            # Let's store it in the connection data
            connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            try:
                jtr_dump_path = smbServer.getJTRdumpPath()
                ntlm_hash_data = outputToJohnFormat( connData['CHALLENGE_MESSAGE']['challenge'], authenticateMessage['user_name'], authenticateMessage['domain_name'], authenticateMessage['lanman'], authenticateMessage['ntlm'] )
                smbServer.log(ntlm_hash_data['hash_string'])
                if jtr_dump_path is not '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], jtr_dump_path)
            except:
                smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)
            respSMBCommand['SessionFlags'] = 1
        else:
            raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand['SecurityBufferOffset'] = 0x48
        respSMBCommand['SecurityBufferLength'] = len(respToken)
        respSMBCommand['Buffer'] = respToken.getData()

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        #os.setregid(65534,65534)
        #os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2TreeConnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved']  = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID']    = recvPacket['TreeID']

        respSMBCommand        = smb2.SMB2TreeConnect_Response()

        treeConnectRequest = smb2.SMB2TreeConnect(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        path = str(recvPacket)[treeConnectRequest['PathOffset']:][:treeConnectRequest['PathLength']]
        UNCOrShare = path.decode('utf-16le')

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        share = searchShare(connId, path.upper(), smbServer)
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
               tid = 1
            else:
               tid = connData['ConnectedShares'].keys()[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            respPacket['TreeID']    = tid
            smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("SMB2_TREE_CONNECT not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            respPacket['Status'] = errorCode
        ##

        if path == 'IPC$':
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_PIPE
            respSMBCommand['ShareFlags'] = 0x30
        else:
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_DISK
            respSMBCommand['ShareFlags'] = 0x0

        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x000f01ff

        respPacket['Data'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

    @staticmethod
    def smb2Create(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2Create_Response()

        ntCreateRequest       = smb2.SMB2Create(recvPacket['Data'])

        respSMBCommand['Buffer'] = '\x00'
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['TreeID']):
             # If we have a rootFid, the path is relative to that fid
             errorCode = STATUS_SUCCESS
             if connData['ConnectedShares'][recvPacket['TreeID']].has_key('path'):
                 path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
             else:
                 path = 'NONE'
                 errorCode = STATUS_ACCESS_DENIED

             deleteOnClose = False

             fileName = os.path.normpath(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le').replace('\\','/'))
             if len(fileName) > 0 and (fileName[0] == '/' or fileName[0] == '\\'):
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             createDisposition = ntCreateRequest['CreateDisposition']
             mode = 0

             if createDisposition == smb2.FILE_SUPERSEDE:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC
                 else:
                     errorCode = STATUS_NO_SUCH_FILE
             elif createDisposition & smb2.FILE_OPEN_IF == smb2.FILE_OPEN_IF:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC
                 else:
                     mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb2.FILE_CREATE == smb2.FILE_CREATE:
                 if os.path.exists(pathName) is True:
                     errorCode = STATUS_OBJECT_NAME_COLLISION
                 else:
                     mode |= os.O_CREAT
             elif createDisposition & smb2.FILE_OPEN == smb2.FILE_OPEN:
                 if os.path.exists(pathName) is not True and smbServer.getRegisteredNamedPipes().has_key(unicode(pathName)) is not True:
                     errorCode = STATUS_NO_SUCH_FILE

             if errorCode == STATUS_SUCCESS:
                 desiredAccess = ntCreateRequest['DesiredAccess']
                 if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                     mode |= os.O_RDONLY
                 if (desiredAccess & smb2.FILE_WRITE_DATA) or (desiredAccess & smb2.GENERIC_WRITE):
                     if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                         mode |= os.O_RDWR #| os.O_APPEND
                     else:
                         mode |= os.O_WRONLY #| os.O_APPEND
                 if desiredAccess & smb2.GENERIC_ALL:
                     mode |= os.O_RDWR #| os.O_APPEND

                 createOptions =  ntCreateRequest['CreateOptions']
                 if mode & os.O_CREAT == os.O_CREAT:
                     if createOptions & smb2.FILE_DIRECTORY_FILE == smb2.FILE_DIRECTORY_FILE:
                         try:
                             # Let's create the directory
                             os.mkdir(pathName)
                             mode = os.O_RDONLY
                         except Exception, e:
                             smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                             errorCode = STATUS_ACCESS_DENIED
                 if createOptions & smb2.FILE_NON_DIRECTORY_FILE == smb2.FILE_NON_DIRECTORY_FILE:
                     # If the file being opened is a directory, the server MUST fail the request with
                     # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                     # response.
                     if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                 if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
                     deleteOnClose = True

                 if errorCode == STATUS_SUCCESS:
                     try:
                         if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                         else:
                            if sys.platform == 'win32':
                               mode |= os.O_BINARY
                            if smbServer.getRegisteredNamedPipes().has_key(unicode(pathName)):
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[unicode(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                     except Exception, e:
                         smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                         #print e
                         fid = 0
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fakefid = uuid.generate()

            respSMBCommand['FileID'] = fakefid
            respSMBCommand['CreateAction'] = createDisposition

            if fid == PIPE_FILE_DESCRIPTOR:
                respSMBCommand['CreationTime']   = 0
                respSMBCommand['LastAccessTime'] = 0
                respSMBCommand['LastWriteTime']  = 0
                respSMBCommand['ChangeTime']     = 0
                respSMBCommand['AllocationSize'] = 4096
                respSMBCommand['EndOfFile']      = 0
                respSMBCommand['FileAttributes'] = 0x80

            else:
                if os.path.isdir(pathName):
                    respSMBCommand['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                else:
                    respSMBCommand['FileAttributes'] = ntCreateRequest['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation('',pathName,level= smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respSMBCommand['CreationTime']   = respInfo['CreationTime']
                    respSMBCommand['LastAccessTime'] = respInfo['LastAccessTime']
                    respSMBCommand['LastWriteTime']  = respInfo['LastWriteTime']
                    respSMBCommand['LastChangeTime'] = respInfo['LastChangeTime']
                    respSMBCommand['FileAttributes'] = respInfo['ExtFileAttributes']
                    respSMBCommand['AllocationSize'] = respInfo['AllocationSize']
                    respSMBCommand['EndOfFile']      = respInfo['EndOfFile']

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose']  = deleteOnClose
                connData['OpenedFiles'][fakefid]['Open']  = {}
                connData['OpenedFiles'][fakefid]['Open']['EnumerationLocation'] = 0
                connData['OpenedFiles'][fakefid]['Open']['EnumerationSearchPattern'] = ''
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respSMBCommand = smb2.SMB2Error()

        if errorCode == STATUS_SUCCESS:
            connData['LastRequest']['SMB2_CREATE'] = respSMBCommand
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Close(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2Close_Response()

        closeRequest = smb2.SMB2Close(recvPacket['Data'])

        if str(closeRequest['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(closeRequest['FileID'])
        else:
            fileID = str(closeRequest['FileID'])

        if connData['OpenedFiles'].has_key(fileID):
             errorCode = STATUS_SUCCESS
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             pathName = connData['OpenedFiles'][fileID]['FileName']
             infoRecord = None
             try:
                 if fileHandle == PIPE_FILE_DESCRIPTOR:
                     connData['OpenedFiles'][fileID]['Socket'].close()
                 elif fileHandle != VOID_FILE_DESCRIPTOR:
                     os.close(fileHandle)
                     infoRecord, errorCode = queryFileInformation(os.path.dirname(pathName), os.path.basename(pathName), smb2.SMB2_FILE_NETWORK_OPEN_INFO)
             except Exception, e:
                 smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                 errorCode = STATUS_INVALID_HANDLE
             else:
                 # Check if the file was marked for removal
                 if connData['OpenedFiles'][fileID]['DeleteOnClose'] is True:
                     try:
                         if os.path.isdir(pathName):
                             shutil.rmtree(connData['OpenedFiles'][fileID]['FileName'])
                         else:
                             os.remove(connData['OpenedFiles'][fileID]['FileName'])
                     except Exception, e:
                         smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                         errorCode = STATUS_ACCESS_DENIED

                 # Now fill out the response
                 if infoRecord is not None:
                     respSMBCommand['CreationTime']   = infoRecord['CreationTime']
                     respSMBCommand['LastAccessTime'] = infoRecord['LastAccessTime']
                     respSMBCommand['LastWriteTime']  = infoRecord['LastWriteTime']
                     respSMBCommand['ChangeTime']     = infoRecord['ChangeTime']
                     respSMBCommand['AllocationSize'] = infoRecord['AllocationSize']
                     respSMBCommand['EndofFile']      = infoRecord['EndOfFile']
                     respSMBCommand['FileAttributes'] = infoRecord['FileAttributes']
                 if errorCode == STATUS_SUCCESS:
                     del(connData['OpenedFiles'][fileID])
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2QueryInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2QueryInfo_Response()

        queryInfo = smb2.SMB2QueryInfo(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['Buffer'] = '\x00'

        if str(queryInfo['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(queryInfo['FileID'])
        else:
            fileID = str(queryInfo['FileID'])

        if connData['ConnectedShares'].has_key(recvPacket['TreeID']):
            if connData['OpenedFiles'].has_key(fileID):
                fileName = connData['OpenedFiles'][fileID]['FileName']

                if queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    if queryInfo['FileInfoClass'] == smb2.SMB2_FILE_INTERNAL_INFO:
                        # No need to call queryFileInformation, we have the data here
                        infoRecord = smb2.FileInternalInformation()
                        infoRecord['IndexNumber'] = fileID
                    else:
                        infoRecord, errorCode = queryFileInformation(os.path.dirname(fileName), os.path.basename(fileName), queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                    infoRecord = queryFsInformation(os.path.dirname(fileName), os.path.basename(fileName), queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                    # Failing for now, until we support it
                    infoRecord = None
                    errorCode = STATUS_ACCESS_DENIED
                else:
                    smbServer.log("queryInfo not supported (%x)" %  queryInfo['InfoType'], logging.ERROR)

                if infoRecord is not None:
                    respSMBCommand['OutputBufferLength'] = len(infoRecord)
                    respSMBCommand['Buffer'] = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2SetInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb2.SMB2SetInfo_Response()

        setInfo = smb2.SMB2SetInfo(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        if str(setInfo['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(setInfo['FileID'])
        else:
            fileID = str(setInfo['FileID'])

        if connData['ConnectedShares'].has_key(recvPacket['TreeID']):
            path     = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            if connData['OpenedFiles'].has_key(fileID):
                pathName = connData['OpenedFiles'][fileID]['FileName']

                if setInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    # The file information is being set
                    informationLevel = setInfo['FileInfoClass']
                    if informationLevel == smb2.SMB2_FILE_DISPOSITION_INFO:
                        infoRecord = smb.SMBSetFileDispositionInfo(setInfo['Buffer'])
                        if infoRecord['DeletePending'] > 0:
                           # Mark this file for removal after closed
                           connData['OpenedFiles'][fileID]['DeleteOnClose'] = True
                    elif informationLevel == smb2.SMB2_FILE_BASIC_INFO:
                        infoRecord = smb.SMBSetFileBasicInfo(setInfo['Buffer'])
                        # Creation time won't be set,  the other ones we play with.
                        atime = infoRecord['LastWriteTime']
                        if atime == 0:
                            atime = -1
                        else:
                            atime = getUnixTime(atime)
                        mtime = infoRecord['ChangeTime']
                        if mtime == 0:
                            mtime = -1
                        else:
                            mtime = getUnixTime(mtime)
                        if atime > 0 and mtime > 0:
                            os.utime(pathName,(atime,mtime))
                    elif informationLevel == smb2.SMB2_FILE_END_OF_FILE_INFO:
                        fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                        infoRecord = smb.SMBSetFileEndOfFileInfo(setInfo['Buffer'])
                        if infoRecord['EndOfFile'] > 0:
                            os.lseek(fileHandle, infoRecord['EndOfFile']-1, 0)
                            os.write(fileHandle, '\x00')
                    elif informationLevel == smb2.SMB2_FILE_RENAME_INFO:
                        renameInfo = smb2.FILE_RENAME_INFORMATION_TYPE_2(setInfo['Buffer'])
                        newPathName = os.path.join(path,renameInfo['FileName'].decode('utf-16le').replace('\\', '/'))
                        if renameInfo['ReplaceIfExists'] == 0 and os.path.exists(newPathName):
                            return [smb2.SMB2Error()], None, STATUS_OBJECT_NAME_COLLISION
                        try:
                             os.rename(pathName,newPathName)
                             connData['OpenedFiles'][fileID]['FileName'] = newPathName
                        except Exception, e:
                             smbServer.log("smb2SetInfo: %s" % e, logging.ERROR)
                             errorCode = STATUS_ACCESS_DENIED
                    else:
                        smbServer.log('Unknown level for set file info! 0x%x' % informationLevel, logging.ERROR)
                        # UNSUPPORTED
                        errorCode =  STATUS_NOT_SUPPORTED
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                #    # The underlying object store information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                #    # The security information is being set.
                #    # Failing for now, until we support it
                #    infoRecord = None
                #    errorCode = STATUS_ACCESS_DENIED
                #elif setInfo['InfoType'] == smb2.SMB2_0_INFO_QUOTA:
                #    # The underlying object store quota information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                else:
                    smbServer.log("setInfo not supported (%x)" %  setInfo['InfoType'], logging.ERROR)

            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Write(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Write_Response()
        writeRequest   = smb2.SMB2Write(recvPacket['Data'])

        respSMBCommand['Buffer'] = '\x00'

        if str(writeRequest['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(writeRequest['FileID'])
        else:
            fileID = str(writeRequest['FileID'])

        if connData['OpenedFiles'].has_key(fileID):
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = writeRequest['Offset']
                     # If we're trying to write past the file end we just skip the write call (Vista does this)
                     if os.lseek(fileHandle, 0, 2) >= offset:
                         os.lseek(fileHandle,offset,0)
                         os.write(fileHandle,writeRequest['Buffer'])
                 else:
                     sock = connData['OpenedFiles'][fileID]['Socket']
                     sock.send(writeRequest['Buffer'])

                 respSMBCommand['Count']    = writeRequest['Length']
                 respSMBCommand['Remaining']= 0xff
             except Exception, e:
                 smbServer.log('SMB2_WRITE: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Read(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Read_Response()
        readRequest   = smb2.SMB2Read(recvPacket['Data'])

        respSMBCommand['Buffer'] = '\x00'

        if str(readRequest['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(readRequest['FileID'])
        else:
            fileID = str(readRequest['FileID'])

        if connData['OpenedFiles'].has_key(fileID):
             fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
             errorCode = 0
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     offset = readRequest['Offset']
                     os.lseek(fileHandle,offset,0)
                     content = os.read(fileHandle,readRequest['Length'])
                 else:
                     sock = connData['OpenedFiles'][fileID]['Socket']
                     content = sock.recv(readRequest['Length'])

                 respSMBCommand['DataOffset']   = 0x50
                 respSMBCommand['DataLength']   = len(content)
                 respSMBCommand['DataRemaining']= 0
                 respSMBCommand['Buffer']       = content
             except Exception, e:
                 smbServer.log('SMB2_READ: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Flush(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Flush_Response()
        flushRequest   = smb2.SMB2Flush(recvPacket['Data'])

        if connData['OpenedFiles'].has_key(str(flushRequest['FileID'])):
             fileHandle = connData['OpenedFiles'][str(flushRequest['FileID'])]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 os.fsync(fileHandle)
             except Exception, e:
                 smbServer.log("SMB2_FLUSH %s" % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode


    @staticmethod
    def smb2QueryDirectory(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        respSMBCommand = smb2.SMB2QueryDirectory_Response()
        queryDirectoryRequest   = smb2.SMB2QueryDirectory(recvPacket['Data'])

        respSMBCommand['Buffer'] = '\x00'

        # The server MUST locate the tree connection, as specified in section 3.3.5.2.11.
        if connData['ConnectedShares'].has_key(recvPacket['TreeID']) is False:
            return [smb2.SMB2Error()], None, STATUS_NETWORK_NAME_DELETED

        # Next, the server MUST locate the open for the directory to be queried
        # If no open is found, the server MUST fail the request with STATUS_FILE_CLOSED
        if str(queryDirectoryRequest['FileID']) == '\xff'*16:
            # Let's take the data from the lastRequest
            if  connData['LastRequest'].has_key('SMB2_CREATE'):
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = str(queryDirectoryRequest['FileID'])
        else:
            fileID = str(queryDirectoryRequest['FileID'])

        if connData['OpenedFiles'].has_key(fileID) is False:
            return [smb2.SMB2Error()], None, STATUS_FILE_CLOSED

        # If the open is not an open to a directory, the request MUST be failed
        # with STATUS_INVALID_PARAMETER.
        if os.path.isdir(connData['OpenedFiles'][fileID]['FileName']) is False:
            return [smb2.SMB2Error()], None, STATUS_INVALID_PARAMETER

        # If any other information class is specified in the FileInformationClass
        # field of the SMB2 QUERY_DIRECTORY Request, the server MUST fail the
        # operation with STATUS_INVALID_INFO_CLASS.
        if queryDirectoryRequest['FileInformationClass'] not in (
        smb2.FILE_DIRECTORY_INFORMATION, smb2.FILE_FULL_DIRECTORY_INFORMATION, smb2.FILEID_FULL_DIRECTORY_INFORMATION,
        smb2.FILE_BOTH_DIRECTORY_INFORMATION, smb2.FILEID_BOTH_DIRECTORY_INFORMATION, smb2.FILENAMES_INFORMATION):
            return [smb2.SMB2Error()], None, STATUS_INVALID_INFO_CLASS

        # If SMB2_REOPEN is set in the Flags field of the SMB2 QUERY_DIRECTORY
        # Request, the server SHOULD<326> set Open.EnumerationLocation to 0
        # and Open.EnumerationSearchPattern to an empty string.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_REOPEN:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = ''

        # If SMB2_RESTART_SCANS is set in the Flags field of the SMB2
        # QUERY_DIRECTORY Request, the server MUST set
        # Open.EnumerationLocation to 0.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_RESTART_SCANS:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0

        # If Open.EnumerationLocation is 0 and Open.EnumerationSearchPattern
        # is an empty string, then Open.EnumerationSearchPattern MUST be set
        # to the search pattern specified in the SMB2 QUERY_DIRECTORY by
        # FileNameOffset and FileNameLength. If FileNameLength is 0, the server
        # SHOULD<327> set Open.EnumerationSearchPattern as "*" to search all entries.

        pattern = queryDirectoryRequest['Buffer'].decode('utf-16le')
        if  connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0 and \
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] == '':
            if pattern == '':
                pattern = '*'
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        # If SMB2_INDEX_SPECIFIED is set and FileNameLength is not zero,
        # the server MUST set Open.EnumerationSearchPattern to the search pattern
        # specified in the request by FileNameOffset and FileNameLength.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_INDEX_SPECIFIED and \
           queryDirectoryRequest['FileNameLength'] > 0:
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        pathName = os.path.join(os.path.normpath(connData['OpenedFiles'][fileID]['FileName']),pattern)
        searchResult, searchCount, errorCode = findFirst2(os.path.dirname(pathName),
                  os.path.basename(pathName),
                  queryDirectoryRequest['FileInformationClass'],
                  smb.ATTR_DIRECTORY, isSMB2 = True )

        if errorCode != STATUS_SUCCESS:
            return [smb2.SMB2Error()], None, errorCode

        if searchCount > 2 and pattern == '*':
            # strip . and ..
            searchCount -= 2
            searchResult = searchResult[2:]

        if searchCount == 0 and connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0:
            return [smb2.SMB2Error()], None, STATUS_NO_SUCH_FILE

        if  connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] < 0:
            return [smb2.SMB2Error()], None, STATUS_NO_MORE_FILES

        totalData = 0
        respData = ''
        for nItem in range(connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'], searchCount):
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] += 1
            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                # If single entry is requested we must clear the NextEntryOffset
                searchResult[nItem]['NextEntryOffset'] = 0
            data = searchResult[nItem].getData()
            lenData = len(data)
            padLen = (8-(lenData % 8)) %8

            if (totalData+lenData) >= queryDirectoryRequest['OutputBufferLength']:
                connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] -= 1
                break
            else:
                respData += data + '\x00'*padLen
                totalData += lenData + padLen

            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                break

        if connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] >= searchCount:
             connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = -1

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['OutputBufferLength'] = totalData
        respSMBCommand['Buffer'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2ChangeNotify(connId, smbServer, recvPacket):

        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED

    @staticmethod
    def smb2Echo(connId, smbServer, recvPacket):

        respSMBCommand = smb2.SMB2Echo_Response()

        return [respSMBCommand], None, STATUS_SUCCESS

    @staticmethod
    def smb2TreeDisconnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2TreeDisconnect_Response()

        if connData['ConnectedShares'].has_key(recvPacket['TreeID']):
            smbServer.log("Disconnecting Share(%d:%s)" % (recvPacket['TreeID'],connData['ConnectedShares'][recvPacket['TreeID']]['shareName']))
            del(connData['ConnectedShares'][recvPacket['TreeID']])
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID


        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Logoff(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Logoff_Response()

        if recvPacket['SessionID'] != connData['Uid']:
            # STATUS_SMB_BAD_UID
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        connData['Uid'] = 0

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Ioctl(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Ioctl_Response()
        ioctlRequest   = smb2.SMB2Ioctl(recvPacket['Data'])

        ioctls = smbServer.getIoctls()
        if ioctls.has_key(ioctlRequest['CtlCode']):
            outputData, errorCode = ioctls[ioctlRequest['CtlCode']](connId, smbServer, ioctlRequest)
            if errorCode == STATUS_SUCCESS:
                respSMBCommand['CtlCode']      = ioctlRequest['CtlCode']
                respSMBCommand['FileID']       = ioctlRequest['FileID']
                respSMBCommand['InputOffset']  = 0
                respSMBCommand['InputCount']   = 0
                respSMBCommand['OutputOffset'] = 0x70
                respSMBCommand['OutputCount']  = len(outputData)
                respSMBCommand['Flags']        = 0
                respSMBCommand['Buffer']       = outputData
            else:
                respSMBCommand = outputData
        else:
            smbServer.log("Ioctl not implemented command: 0x%x" % ioctlRequest['CtlCode'],logging.DEBUG)
            errorCode = STATUS_INVALID_DEVICE_REQUEST
            respSMBCommand = smb2.SMB2Error()

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Lock(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Lock_Response()

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Cancel(connId, smbServer, recvPacket):
        # I'm actually doing nothing
        return [smb2.SMB2Error()], None, STATUS_CANCELLED

    @staticmethod
    def default(connId, smbServer, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'],logging.DEBUG)
        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED

class Ioctls:
   @staticmethod
   def fsctlDfsGetReferrals(connId, smbServer, ioctlRequest):
        return smb2.SMB2Error(), STATUS_FS_DRIVER_REQUIRED

   @staticmethod
   def fsctlPipeTransceive(connId, smbServer, ioctlRequest):
        connData = smbServer.getConnectionData(connId)

        ioctlResponse = ''

        if connData['OpenedFiles'].has_key(str(ioctlRequest['FileID'])):
             fileHandle = connData['OpenedFiles'][str(ioctlRequest['FileID'])]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     errorCode = STATUS_INVALID_DEVICE_REQUEST
                 else:
                     sock = connData['OpenedFiles'][str(ioctlRequest['FileID'])]['Socket']
                     sock.sendall(ioctlRequest['Buffer'])
                     ioctlResponse = sock.recv(ioctlRequest['MaxOutputResponse'])
             except Exception, e:
                 smbServer.log('fsctlPipeTransceive: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_DEVICE_REQUEST

        smbServer.setConnectionData(connId, connData)
        return ioctlResponse, errorCode

   @staticmethod
   def fsctlValidateNegotiateInfo(connId, smbServer, ioctlRequest):
        connData = smbServer.getConnectionData(connId)

        errorCode = STATUS_SUCCESS

        validateNegotiateInfo = smb2.VALIDATE_NEGOTIATE_INFO(ioctlRequest['Buffer'])
        validateNegotiateInfo['Capabilities'] = 0
        validateNegotiateInfo['Guid'] = 'A'*16
        validateNegotiateInfo['SecurityMode'] = 1
        validateNegotiateInfo['Dialects'] = (smb2.SMB2_DIALECT_002,)

        smbServer.setConnectionData(connId, connData)
        return validateNegotiateInfo.getData(), errorCode


class SMBSERVERHandler(SocketServer.BaseRequestHandler):
    def __init__(self, request, client_address, server, select_poll = False):
        self.__SMB = server
        self.__ip, self.__port = client_address
        self.__request = request
        self.__connId = threading.currentThread().getName()
        self.__timeOut = 60*5
        self.__select_poll = select_poll
        #self.__connId = os.getpid()
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.addConnection(self.__connId, self.__ip, self.__port)
        while True:
            try:
                # Firt of all let's get the NETBIOS packet
                session = nmb.NetBIOSTCPSession(self.__SMB.getServerName(),'HOST', self.__ip, sess_port = self.__port, sock = self.__request, select_poll = self.__select_poll)
                try:
                    p = session.recv_packet(self.__timeOut)
                except nmb.NetBIOSTimeout:
                    raise
                except nmb.NetBIOSError:
                    break

                if p.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                   # Someone is requesting a session, we're gonna accept them all :)
                   _, rn, my = p.get_trailer().split(' ')
                   remote_name = nmb.decode_name('\x20'+rn)
                   myname = nmb.decode_name('\x20'+my)
                   self.__SMB.log("NetBIOS Session request (%s,%s,%s)" % (self.__ip, remote_name[1].strip(), myname[1]))
                   r = nmb.NetBIOSSessionPacket()
                   r.set_type(nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                   r.set_trailer(p.get_trailer())
                   self.__request.send(r.rawData())
                else:
                   resp = self.__SMB.processRequest(self.__connId, p.get_trailer())
                   # Send all the packets recevied. Except for big transactions this should be
                   # a single packet
                   for i in resp:
                       session.send_packet(str(i))
            except Exception, e:
                self.__SMB.log("Handle: %s" % e)
                #import traceback
                #traceback.print_exc()
                break

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        self.__SMB.log("Closing down connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.removeConnection(self.__connId)
        return SocketServer.BaseRequestHandler.finish(self)

class SMBSERVER(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
#class SMBSERVER(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser = None):
        SocketServer.TCPServer.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        # Server name and OS to be presented whenever is necessary
        self.__serverName   = ''
        self.__serverOS     = ''
        self.__serverDomain = ''
        self.__challenge    = ''
        self.__log          = None

        # Our ConfigParser data
        self.__serverConfig = config_parser

        # Our credentials to be used during the server's lifetime
        self.__credentials = {}

        # Our log file
        self.__logFile = ''

        # Registered Named Pipes, format is PipeName,Socket
        self.__registeredNamedPipes = {}

        # JTR dump path
        self.__jtr_dump_path = ''

        # SMB2 Support flag = default not active
        self.__SMB2Support = False

        # Our list of commands we will answer, by default the NOT IMPLEMENTED one
        self.__smbCommandsHandler = SMBCommands()
        self.__smbTrans2Handler   = TRANS2Commands()
        self.__smbTransHandler    = TRANSCommands()
        self.__smbNTTransHandler  = NTTRANSCommands()
        self.__smb2CommandsHandler = SMB2Commands()
        self.__IoctlHandler       = Ioctls()

        self.__smbNTTransCommands = {
        # NT IOCTL, can't find doc for this
        0xff                               :self.__smbNTTransHandler.default
        }

        self.__smbTransCommands  = {
'\\PIPE\\LANMAN'                       :self.__smbTransHandler.lanMan,
smb.SMB.TRANS_TRANSACT_NMPIPE          :self.__smbTransHandler.transactNamedPipe,
        }
        self.__smbTrans2Commands = {
 smb.SMB.TRANS2_FIND_FIRST2            :self.__smbTrans2Handler.findFirst2,
 smb.SMB.TRANS2_FIND_NEXT2             :self.__smbTrans2Handler.findNext2,
 smb.SMB.TRANS2_QUERY_FS_INFORMATION   :self.__smbTrans2Handler.queryFsInformation,
 smb.SMB.TRANS2_QUERY_PATH_INFORMATION :self.__smbTrans2Handler.queryPathInformation,
 smb.SMB.TRANS2_QUERY_FILE_INFORMATION :self.__smbTrans2Handler.queryFileInformation,
 smb.SMB.TRANS2_SET_FILE_INFORMATION   :self.__smbTrans2Handler.setFileInformation,
 smb.SMB.TRANS2_SET_PATH_INFORMATION   :self.__smbTrans2Handler.setPathInformation
        }

        self.__smbCommands = {
 #smb.SMB.SMB_COM_FLUSH:              self.__smbCommandsHandler.smbComFlush,
 smb.SMB.SMB_COM_CREATE_DIRECTORY:   self.__smbCommandsHandler.smbComCreateDirectory,
 smb.SMB.SMB_COM_DELETE_DIRECTORY:   self.__smbCommandsHandler.smbComDeleteDirectory,
 smb.SMB.SMB_COM_RENAME:             self.__smbCommandsHandler.smbComRename,
 smb.SMB.SMB_COM_DELETE:             self.__smbCommandsHandler.smbComDelete,
 smb.SMB.SMB_COM_NEGOTIATE:          self.__smbCommandsHandler.smbComNegotiate,
 smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.__smbCommandsHandler.smbComSessionSetupAndX,
 smb.SMB.SMB_COM_LOGOFF_ANDX:        self.__smbCommandsHandler.smbComLogOffAndX,
 smb.SMB.SMB_COM_TREE_CONNECT_ANDX:  self.__smbCommandsHandler.smbComTreeConnectAndX,
 smb.SMB.SMB_COM_TREE_DISCONNECT:    self.__smbCommandsHandler.smbComTreeDisconnect,
 smb.SMB.SMB_COM_ECHO:               self.__smbCommandsHandler.smbComEcho,
 smb.SMB.SMB_COM_QUERY_INFORMATION:  self.__smbCommandsHandler.smbQueryInformation,
 smb.SMB.SMB_COM_TRANSACTION2:       self.__smbCommandsHandler.smbTransaction2,
 smb.SMB.SMB_COM_TRANSACTION:        self.__smbCommandsHandler.smbTransaction,
 # Not needed for now
 smb.SMB.SMB_COM_NT_TRANSACT:        self.__smbCommandsHandler.smbNTTransact,
 smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: self.__smbCommandsHandler.smbQueryInformationDisk,
 smb.SMB.SMB_COM_OPEN_ANDX:          self.__smbCommandsHandler.smbComOpenAndX,
 smb.SMB.SMB_COM_QUERY_INFORMATION2: self.__smbCommandsHandler.smbComQueryInformation2,
 smb.SMB.SMB_COM_READ_ANDX:          self.__smbCommandsHandler.smbComReadAndX,
 smb.SMB.SMB_COM_READ:               self.__smbCommandsHandler.smbComRead,
 smb.SMB.SMB_COM_WRITE_ANDX:         self.__smbCommandsHandler.smbComWriteAndX,
 smb.SMB.SMB_COM_WRITE:              self.__smbCommandsHandler.smbComWrite,
 smb.SMB.SMB_COM_CLOSE:              self.__smbCommandsHandler.smbComClose,
 smb.SMB.SMB_COM_LOCKING_ANDX:       self.__smbCommandsHandler.smbComLockingAndX,
 smb.SMB.SMB_COM_NT_CREATE_ANDX:     self.__smbCommandsHandler.smbComNtCreateAndX,
 0xFF:                               self.__smbCommandsHandler.default
}

        self.__smb2Ioctls = {
 smb2.FSCTL_DFS_GET_REFERRALS:            self.__IoctlHandler.fsctlDfsGetReferrals,
# smb2.FSCTL_PIPE_PEEK:                    self.__IoctlHandler.fsctlPipePeek,
# smb2.FSCTL_PIPE_WAIT:                    self.__IoctlHandler.fsctlPipeWait,
 smb2.FSCTL_PIPE_TRANSCEIVE:              self.__IoctlHandler.fsctlPipeTransceive,
# smb2.FSCTL_SRV_COPYCHUNK:                self.__IoctlHandler.fsctlSrvCopyChunk,
# smb2.FSCTL_SRV_ENUMERATE_SNAPSHOTS:      self.__IoctlHandler.fsctlSrvEnumerateSnapshots,
# smb2.FSCTL_SRV_REQUEST_RESUME_KEY:       self.__IoctlHandler.fsctlSrvRequestResumeKey,
# smb2.FSCTL_SRV_READ_HASH:                self.__IoctlHandler.fsctlSrvReadHash,
# smb2.FSCTL_SRV_COPYCHUNK_WRITE:          self.__IoctlHandler.fsctlSrvCopyChunkWrite,
# smb2.FSCTL_LMR_REQUEST_RESILIENCY:       self.__IoctlHandler.fsctlLmrRequestResiliency,
# smb2.FSCTL_QUERY_NETWORK_INTERFACE_INFO: self.__IoctlHandler.fsctlQueryNetworkInterfaceInfo,
# smb2.FSCTL_SET_REPARSE_POINT:            self.__IoctlHandler.fsctlSetReparsePoint,
# smb2.FSCTL_DFS_GET_REFERRALS_EX:         self.__IoctlHandler.fsctlDfsGetReferralsEx,
# smb2.FSCTL_FILE_LEVEL_TRIM:              self.__IoctlHandler.fsctlFileLevelTrim,
 smb2.FSCTL_VALIDATE_NEGOTIATE_INFO:      self.__IoctlHandler.fsctlValidateNegotiateInfo,
}

        self.__smb2Commands = {
 smb2.SMB2_NEGOTIATE:       self.__smb2CommandsHandler.smb2Negotiate,
 smb2.SMB2_SESSION_SETUP:   self.__smb2CommandsHandler.smb2SessionSetup,
 smb2.SMB2_LOGOFF:          self.__smb2CommandsHandler.smb2Logoff,
 smb2.SMB2_TREE_CONNECT:    self.__smb2CommandsHandler.smb2TreeConnect,
 smb2.SMB2_TREE_DISCONNECT: self.__smb2CommandsHandler.smb2TreeDisconnect,
 smb2.SMB2_CREATE:          self.__smb2CommandsHandler.smb2Create,
 smb2.SMB2_CLOSE:           self.__smb2CommandsHandler.smb2Close,
 smb2.SMB2_FLUSH:           self.__smb2CommandsHandler.smb2Flush,
 smb2.SMB2_READ:            self.__smb2CommandsHandler.smb2Read,
 smb2.SMB2_WRITE:           self.__smb2CommandsHandler.smb2Write,
 smb2.SMB2_LOCK:            self.__smb2CommandsHandler.smb2Lock,
 smb2.SMB2_IOCTL:           self.__smb2CommandsHandler.smb2Ioctl,
 smb2.SMB2_CANCEL:          self.__smb2CommandsHandler.smb2Cancel,
 smb2.SMB2_ECHO:            self.__smb2CommandsHandler.smb2Echo,
 smb2.SMB2_QUERY_DIRECTORY: self.__smb2CommandsHandler.smb2QueryDirectory,
 smb2.SMB2_CHANGE_NOTIFY:   self.__smb2CommandsHandler.smb2ChangeNotify,
 smb2.SMB2_QUERY_INFO:      self.__smb2CommandsHandler.smb2QueryInfo,
 smb2.SMB2_SET_INFO:        self.__smb2CommandsHandler.smb2SetInfo,
# smb2.SMB2_OPLOCK_BREAK:    self.__smb2CommandsHandler.smb2SessionSetup,
 0xFF:                      self.__smb2CommandsHandler.default
}

        # List of active connections
        self.__activeConnections = {}

    def getIoctls(self):
        return self.__smb2Ioctls

    def getCredentials(self):
        return self.__credentials

    def removeConnection(self, name):
        try:
           del(self.__activeConnections[name])
        except:
           pass
        self.log("Remaining connections %s" % self.__activeConnections.keys())

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        # Let's init with some know stuff we will need to have
        # TODO: Document what's in there
        #print "Current Connections", self.__activeConnections.keys()
        self.__activeConnections[name]['PacketNum']       = 0
        self.__activeConnections[name]['ClientIP']        = ip
        self.__activeConnections[name]['ClientPort']      = port
        self.__activeConnections[name]['Uid']             = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles']     = {}
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs']            = {}
        self.__activeConnections[name]['LastRequest']     = {}

    def getActiveConnections(self):
        return self.__activeConnections

    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        #print "setConnectionData"
        #print self.__activeConnections

    def getConnectionData(self, connId, checkStatus = True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if conn.has_key('Authenticated') is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

    def getRegisteredNamedPipes(self):
        return self.__registeredNamedPipes

    def registerNamedPipe(self, pipeName, address):
        self.__registeredNamedPipes[unicode(pipeName)] = address
        return True

    def unregisterNamedPipe(self, pipeName):
        if self.__registeredNamedPipes.has_key(pipeName):
            del(self.__registeredNamedPipes[unicode(pipeName)])
            return True
        return False

    def unregisterTransaction(self, transCommand):
        if self.__smbTransCommands.has_key(transCommand):
           del(self.__smbTransCommands[transCommand])

    def hookTransaction(self, transCommand, callback):
        # If you call this function, callback will replace
        # the current Transaction sub command.
        # (don't get confused with the Transaction smbCommand)
        # If the transaction sub command doesn't not exist, it is added
        # If the transaction sub command exists, it returns the original function         # replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, recvPacket, parameters, data, maxDataCount=0)
        #
        # WHERE:
        #
        # connId      : the connection Id, used to grab/update information about
        #               the current connection
        # smbServer   : the SMBServer instance available for you to ask
        #               configuration data
        # recvPacket  : the full SMBPacket that triggered this command
        # parameters  : the transaction parameters
        # data        : the transaction data
        # maxDataCount: the max amount of data that can be transfered agreed
        #               with the client
        #
        # and MUST return:
        # respSetup, respParameters, respData, errorCode
        #
        # WHERE:
        #
        # respSetup: the setup response of the transaction
        # respParameters: the parameters response of the transaction
        # respData: the data reponse of the transaction
        # errorCode: the NT error code

        if self.__smbTransCommands.has_key(transCommand):
           originalCommand = self.__smbTransCommands[transCommand]
        else:
           originalCommand = None

        self.__smbTransCommands[transCommand] = callback
        return originalCommand

    def unregisterTransaction2(self, transCommand):
        if self.__smbTrans2Commands.has_key(transCommand):
           del(self.__smbTrans2Commands[transCommand])

    def hookTransaction2(self, transCommand, callback):
        # Here we should add to __smbTrans2Commands
        # Same description as Transaction
        if self.__smbTrans2Commands.has_key(transCommand):
           originalCommand = self.__smbTrans2Commands[transCommand]
        else:
           originalCommand = None

        self.__smbTrans2Commands[transCommand] = callback
        return originalCommand

    def unregisterNTTransaction(self, transCommand):
        if self.__smbNTTransCommands.has_key(transCommand):
           del(self.__smbNTTransCommands[transCommand])

    def hookNTTransaction(self, transCommand, callback):
        # Here we should add to __smbNTTransCommands
        # Same description as Transaction
        if self.__smbNTTransCommands.has_key(transCommand):
           originalCommand = self.__smbNTTransCommands[transCommand]
        else:
           originalCommand = None

        self.__smbNTTransCommands[transCommand] = callback
        return originalCommand

    def unregisterSmbCommand(self, smbCommand):
        if self.__smbCommands.has_key(smbCommand):
           del(self.__smbCommands[smbCommand])

    def hookSmbCommand(self, smbCommand, callback):
        # Here we should add to self.__smbCommands
        # If you call this function, callback will replace
        # the current smbCommand.
        # If smbCommand doesn't not exist, it is added
        # If SMB command exists, it returns the original function replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, SMBCommand, recvPacket)
        #
        # WHERE:
        #
        # connId    : the connection Id, used to grab/update information about
        #             the current connection
        # smbServer : the SMBServer instance available for you to ask
        #             configuration data
        # SMBCommand: the SMBCommand itself, with its data and parameters.
        #             Check smb.py:SMBCommand() for a reference
        # recvPacket: the full SMBPacket that triggered this command
        #
        # and MUST return:
        # <list of respSMBCommands>, <list of packets>, errorCode
        # <list of packets> has higher preference over commands, in case you
        # want to change the whole packet
        # errorCode: the NT error code
        #
        # For SMB_COM_TRANSACTION2, SMB_COM_TRANSACTION and SMB_COM_NT_TRANSACT
        # the callback function is slightly different:
        #
        # callback(connId, smbServer, SMBCommand, recvPacket, transCommands)
        #
        # WHERE:
        #
        # transCommands: a list of transaction subcommands already registered
        #

        if self.__smbCommands.has_key(smbCommand):
           originalCommand = self.__smbCommands[smbCommand]
        else:
           originalCommand = None

        self.__smbCommands[smbCommand] = callback
        return originalCommand

    def unregisterSmb2Command(self, smb2Command):
        if self.__smb2Commands.has_key(smb2Command):
           del(self.__smb2Commands[smb2Command])

    def hookSmb2Command(self, smb2Command, callback):
        if self.__smb2Commands.has_key(smb2Command):
           originalCommand = self.__smb2Commands[smb2Command]
        else:
           originalCommand = None

        self.__smb2Commands[smb2Command] = callback
        return originalCommand

    def log(self, msg, level=logging.INFO):
        self.__log.log(level,msg)

    def getServerName(self):
        return self.__serverName

    def getServerOS(self):
        return self.__serverOS

    def getServerDomain(self):
        return self.__serverDomain

    def getSMBChallenge(self):
        return self.__challenge

    def getServerConfig(self):
        return self.__serverConfig

    def setServerConfig(self, config):
        self.__serverConfig = config

    def getJTRdumpPath(self):
        return self.__jtr_dump_path

    def verify_request(self, request, client_address):
        # TODO: Control here the max amount of processes we want to launch
        # returning False, closes the connection
        return True

    def processRequest(self, connId, data):

        # TODO: Process batched commands.
        isSMB2      = False
        SMBCommand  = None
        try:
            packet = smb.NewSMBPacket(data = data)
            SMBCommand  = smb.SMBCommand(packet['Data'][0])
        except:
            # Maybe a SMB2 packet?
            packet = smb2.SMB2Packet(data = data)
            isSMB2 = True

        # We might have compound requests
        compoundedPacketsResponse = []
        compoundedPackets         = []
        try:
            # Search out list of implemented commands
            # We provide them with:
            # connId      : representing the data for this specific connection
            # self        : the SMBSERVER if they want to ask data to it
            # SMBCommand  : the SMBCommand they are expecting to process
            # packet      : the received packet itself, in case they need more data than the actual command
            # Only for Transactions
            # transCommand: a list of transaction subcommands
            # We expect to get:
            # respCommands: a list of answers for the commands processed
            # respPacket  : if the commands chose to directly craft packet/s, we use this and not the previous
            #               this MUST be a list
            # errorCode   : self explanatory
            if isSMB2 is False:
                if packet['Command'] == smb.SMB.SMB_COM_TRANSACTION2:
                    respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                  connId,
                                  self,
                                  SMBCommand,
                                  packet,
                                  self.__smbTrans2Commands)
                elif packet['Command'] == smb.SMB.SMB_COM_NT_TRANSACT:
                    respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                  connId,
                                  self,
                                  SMBCommand,
                                  packet,
                                  self.__smbNTTransCommands)
                elif packet['Command'] == smb.SMB.SMB_COM_TRANSACTION:
                    respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                  connId,
                                  self,
                                  SMBCommand,
                                  packet,
                                  self.__smbTransCommands)
                else:
                    if self.__smbCommands.has_key(packet['Command']):
                       if self.__SMB2Support is True:
                           if packet['Command'] == smb.SMB.SMB_COM_NEGOTIATE:
                               try:
                                   respCommands, respPackets, errorCode = self.__smb2Commands[smb2.SMB2_NEGOTIATE](connId, self, packet, True)
                                   isSMB2 = True
                               except Exception, e:
                                   self.log('SMB2_NEGOTIATE: %s' % e, logging.ERROR)
                                   # If something went wrong, let's fallback to SMB1
                                   respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                       connId,
                                       self,
                                       SMBCommand,
                                       packet)
                                   #self.__SMB2Support = False
                                   pass
                           else:
                               respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                       connId,
                                       self,
                                       SMBCommand,
                                       packet)
                       else:
                           respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                       connId,
                                       self,
                                       SMBCommand,
                                       packet)
                    else:
                       respCommands, respPackets, errorCode = self.__smbCommands[255](connId, self, SMBCommand, packet)

                compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                compoundedPackets.append(packet)

            else:
                done = False
                while not done:
                    if self.__smb2Commands.has_key(packet['Command']):
                       if self.__SMB2Support is True:
                           respCommands, respPackets, errorCode = self.__smb2Commands[packet['Command']](
                                   connId,
                                   self,
                                   packet)
                       else:
                           respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                    else:
                       respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                    # Let's store the result for this compounded packet
                    compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                    compoundedPackets.append(packet)
                    if packet['NextCommand'] != 0:
                        data = data[packet['NextCommand']:]
                        packet = smb2.SMB2Packet(data = data)
                    else:
                        done = True

        except Exception, e:
            #import traceback
            #traceback.print_exc()
            # Something wen't wrong, defaulting to Bad user ID
            self.log('processRequest (0x%x,%s)' % (packet['Command'],e), logging.ERROR)
            raise

        # We prepare the response packet to commands don't need to bother about that.
        connData    = self.getConnectionData(connId, False)

        # Force reconnection loop.. This is just a test.. client will send me back credentials :)
        #connData['PacketNum'] += 1
        #if connData['PacketNum'] == 15:
        #    connData['PacketNum'] = 0
        #    # Something wen't wrong, defaulting to Bad user ID
        #    self.log('Sending BAD USER ID!', logging.ERROR)
        #    #raise
        #    packet['Flags1'] |= smb.SMB.FLAGS1_REPLY
        #    packet['Flags2'] = 0
        #    errorCode = STATUS_SMB_BAD_UID
        #    packet['ErrorCode']   = errorCode >> 16
        #    packet['ErrorClass']  = errorCode & 0xff
        #    return [packet]

        self.setConnectionData(connId, connData)

        packetsToSend = []
        for packetNum in range(len(compoundedPacketsResponse)):
            respCommands, respPackets, errorCode = compoundedPacketsResponse[packetNum]
            packet = compoundedPackets[packetNum]
            if respPackets is None:
                for respCommand in respCommands:
                    if isSMB2 is False:
                        respPacket           = smb.NewSMBPacket()
                        respPacket['Flags1'] = smb.SMB.FLAGS1_REPLY

                        # TODO this should come from a per session configuration
                        respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | packet['Flags2'] & smb.SMB.FLAGS2_UNICODE
                        #respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES
                        #respPacket['Flags1'] = 0x98
                        #respPacket['Flags2'] = 0xc807


                        respPacket['Tid']    = packet['Tid']
                        respPacket['Mid']    = packet['Mid']
                        respPacket['Pid']    = packet['Pid']
                        respPacket['Uid']    = connData['Uid']

                        respPacket['ErrorCode']   = errorCode >> 16
                        respPacket['_reserved']   = errorCode >> 8 & 0xff
                        respPacket['ErrorClass']  = errorCode & 0xff
                        respPacket.addCommand(respCommand)

                        packetsToSend.append(respPacket)
                    else:
                        respPacket = smb2.SMB2Packet()
                        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
                        if packetNum > 0:
                            respPacket['Flags'] |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
                        respPacket['Status']    = errorCode
                        respPacket['CreditRequestResponse'] = packet['CreditRequestResponse']
                        respPacket['Command']   = packet['Command']
                        respPacket['CreditCharge'] = packet['CreditCharge']
                        #respPacket['CreditCharge'] = 0
                        respPacket['Reserved']  = packet['Reserved']
                        respPacket['SessionID'] = connData['Uid']
                        respPacket['MessageID'] = packet['MessageID']
                        respPacket['TreeID']    = packet['TreeID']
                        respPacket['Data']      = str(respCommand)
                        packetsToSend.append(respPacket)
            else:
                # The SMBCommand took care of building the packet
                packetsToSend = respPackets

        if isSMB2 is True:
            # Let's build a compound answer
            finalData = ''
            i = 0
            for i in range(len(packetsToSend)-1):
                packet = packetsToSend[i]
                # Align to 8-bytes
                padLen = (8 - (len(packet) % 8) ) % 8
                packet['NextCommand'] = len(packet) + padLen
                finalData += str(packet) + padLen*'\x00'

            # Last one
            finalData += str(packetsToSend[len(packetsToSend)-1])
            packetsToSend = [finalData]

        # We clear the compound requests
        connData['LastRequest'] = {}

        return packetsToSend

    def processConfigFile(self, configFile = None):
        # TODO: Do a real config parser
        if self.__serverConfig is None:
            if configFile is None:
                configFile = 'smb.conf'
            self.__serverConfig = ConfigParser.ConfigParser()
            self.__serverConfig.read(configFile)

        self.__serverName   = self.__serverConfig.get('global','server_name')
        self.__serverOS     = self.__serverConfig.get('global','server_os')
        self.__serverDomain = self.__serverConfig.get('global','server_domain')
        self.__logFile      = self.__serverConfig.get('global','log_file')
        if self.__serverConfig.has_option('global', 'challenge'):
            self.__challenge    = self.__serverConfig.get('global', 'challenge')
        else:
            self.__challenge    = 'A'*8

        if self.__serverConfig.has_option("global", "jtr_dump_path"):
            self.__jtr_dump_path = self.__serverConfig.get("global", "jtr_dump_path")

        if self.__serverConfig.has_option("global", "SMB2Support"):
            self.__SMB2Support = self.__serverConfig.getboolean("global","SMB2Support")
        else:
            self.__SMB2Support = False

        if self.__logFile != 'None':
            logging.basicConfig(filename = self.__logFile,
                             level = logging.DEBUG,
                             format="%(asctime)s: %(levelname)s: %(message)s",
                             datefmt = '%m/%d/%Y %I:%M:%S %p')
        self.__log        = LOG

        # Process the credentials
        credentials_fname = self.__serverConfig.get('global','credentials_file')
        if credentials_fname is not "":
            cred = open(credentials_fname)
            line = cred.readline()
            while line:
                name, domain, lmhash, nthash = line.split(':')
                self.__credentials[name] = (domain, lmhash, nthash.strip('\r\n'))
                line = cred.readline()
            cred.close()
        self.log('Config file parsed')

# For windows platforms, opening a directory is not an option, so we set a void FD
VOID_FILE_DESCRIPTOR = -1
PIPE_FILE_DESCRIPTOR = -2
