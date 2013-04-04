'***************************************************************************
'*                                  _   _ ____  _
'*  Project                     ___| | | |  _ \| |
'*                             / __| | | | |_) | |
'*                            | (__| |_| |  _ <| |___
'*                             \___|\___/|_| \_\_____|
'*
'* Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
'*
'* This software is licensed as described in the file COPYING, which
'* you should have received as part of this distribution. The terms
'* are also available at http://curl.haxx.se/docs/copyright.html.
'*
'* You may opt to use, copy, modify, merge, publish, distribute and/or sell
'* copies of the Software, and permit persons to whom the Software is
'* furnished to do so, under the terms of the COPYING file.
'*
'* This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
'* KIND, either express or implied.
'*
'***************************************************************************
'* Script to fetch certdata.txt from Mozilla.org site and create a
'* ca-bundle.crt for use with OpenSSL / libcurl / libcurl bindings
'* Requires WinHttp.WinHttpRequest.5.1 and ADODB.Stream which are part of
'* W2000 SP3 or later, WXP SP1 or later, W2003 Server SP1 or later.
'* Hacked by Guenter Knauf
'***************************************************************************
Option Explicit
Const myVersion = "0.3.7"

Const myUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1"

Const myOpenssl = "openssl.exe"

Const myCdSavF = FALSE       ' Flag: save downloaded data to file certdata.txt
Const myCaBakF = TRUE        ' Flag: backup existing ca-bundle certificate
Const myAskLiF = TRUE        ' Flag: display certdata.txt license agreement
Const myAskTiF = TRUE        ' Flag: ask to include certificate text info
Const myWrapLe = 76          ' Default length of base64 output lines

'******************* Nothing to configure below! *******************
Dim objShell, objNetwork, objFSO, objHttp
Dim myBase, mySelf, myFh, myTmpFh, myCdData, myCdFile, myCaFile, myTmpName, myBakNum, myOptTxt, i
Set objNetwork = WScript.CreateObject("WScript.Network")
Set objShell = WScript.CreateObject("WScript.Shell")
Set objFSO = WScript.CreateObject("Scripting.FileSystemObject")
Set objHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1")
If objHttp Is Nothing Then Set objHttp = WScript.CreateObject("WinHttp.WinHttpRequest")
myBase = Left(WScript.ScriptFullName, InstrRev(WScript.ScriptFullName, "\"))
mySelf = Left(WScript.ScriptName, InstrRev(WScript.ScriptName, ".") - 1) & " " & myVersion
myCdFile = Mid(myUrl, InstrRev(myUrl, "/") + 1, InstrRev(myUrl, "?") - InstrRev(myUrl, "/") - 1)
myCaFile = "ca-bundle.crt"
myTmpName = InputBox("Enter output filename:", mySelf, myCaFile)
If Not (myTmpName = "") Then
  myCaFile = myTmpName
End If
' Lets ignore SSL invalid cert errors
objHttp.Option(4) = 256 + 512 + 4096 + 8192
objHttp.SetTimeouts 0, 5000, 10000, 10000
objHttp.Open "GET", myUrl, FALSE
objHttp.setRequestHeader "User-Agent", WScript.ScriptName & "/" & myVersion
objHttp.Send ""
If Not (objHttp.statusText = "OK") Then
  MsgBox("Failed to download '" & myCdFile & "': " & objHttp.statusText), vbCritical, mySelf
  WScript.Quit 1
End If
' Convert data from ResponseBody instead of using ResponseText because of UTF-8
myCdData = ConvertBinaryData(objHttp.ResponseBody)
Set objHttp = Nothing
' Write received data to file if enabled
If (myCdSavF = TRUE) Then
  Set myFh = objFSO.OpenTextFile(myCdFile, 2, TRUE)
  myFh.Write myCdData
  myFh.Close
End If
' Backup exitsing ca-bundle certificate file
If (myCaBakF = TRUE) Then
  If objFSO.FileExists(myCaFile) Then
    Dim myBakFile, b
    b = 1
    myBakFile = myCaFile & ".~" & b & "~"
    While objFSO.FileExists(myBakFile)
      b = b + 1
      myBakFile = myCaFile & ".~" & b & "~"
    Wend
    Set myTmpFh = objFSO.GetFile(myCaFile)
    myTmpFh.Move myBakFile
  End If
End If
If (myAskTiF = TRUE) Then
  If (6 = objShell.PopUp("Do you want to include text information about each certificate?" & vbLf & _
          "(requires OpenSSL commandline in current directory or in search path)",, _
          mySelf, vbQuestion + vbYesNo + vbDefaultButton2)) Then
    myOptTxt = TRUE
  Else
    myOptTxt = FALSE
  End If
End If
' Process the received data
Dim myLines, myPattern, myInsideCert, myInsideLicense, myLicenseText, myNumCerts, myNumSkipped
Dim myLabel, myOctets, myData, myPem, myRev, myUntrusted, j
myNumSkipped = 0
myNumCerts = 0
myData = ""
myLines = Split(myCdData, vbLf, -1)
Set myFh = objFSO.OpenTextFile(myCaFile, 2, TRUE)
myFh.Write "##" & vbLf
myFh.Write "## " & myCaFile & " -- Bundle of CA Root Certificates" & vbLf
myFh.Write "##" & vbLf
myFh.Write "## Converted at: " & Now & vbLf
myFh.Write "##" & vbLf
myFh.Write "## This is a bundle of X.509 certificates of public Certificate Authorities" & vbLf
myFh.Write "## (CA). These were automatically extracted from Mozilla's root certificates" & vbLf
myFh.Write "## file (certdata.txt).  This file can be found in the mozilla source tree:" & vbLf
myFh.Write "## '/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt'" & vbLf
myFh.Write "##" & vbLf
myFh.Write "## It contains the certificates in PEM format and therefore" & vbLf
myFh.Write "## can be directly used with curl / libcurl / php_curl, or with" & vbLf
myFh.Write "## an Apache+mod_ssl webserver for SSL client authentication." & vbLf
myFh.Write "## Just configure this file as the SSLCACertificateFile." & vbLf
myFh.Write "##" & vbLf
myFh.Write vbLf
For i = 0 To UBound(myLines)
  If InstrRev(myLines(i), "CKA_LABEL ") Then
    myPattern = "^CKA_LABEL\s+[A-Z0-9]+\s+""(.+?)"""
    myLabel = RegExprFirst(myPattern, myLines(i))
  End If
  If (myInsideCert = TRUE) Then
    If InstrRev(myLines(i), "END") Then
      myInsideCert = FALSE
      While (i < UBound(myLines)) And Not (myLines(i) = "#")
        i = i + 1
        If (InstrRev(myLines(i), "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED") Or _
           InstrRev(myLines(i), "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUST_UNKNOWN")) Then
          myUntrusted = TRUE
        End If
      Wend
      If (myUntrusted = TRUE) Then
        myNumSkipped = myNumSkipped + 1
      Else
        myFh.Write myLabel & vbLf
        myFh.Write String(Len(myLabel), "=") & vbLf
        myPem = "-----BEGIN CERTIFICATE-----" & vbLf & _
                Base64Encode(myData) & vbLf & _
                "-----END CERTIFICATE-----" & vbLf
        If (myOptTxt = FALSE) Then
          myFh.Write myPem & vbLf
        Else
          Dim myCmd, myRval, myTmpIn, myTmpOut
          myTmpIn = objFSO.GetSpecialFolder(2).Path & "\" & objFSO.GetTempName
          myTmpOut = objFSO.GetSpecialFolder(2).Path & "\" & objFSO.GetTempName
          Set myTmpFh = objFSO.OpenTextFile(myTmpIn, 2, TRUE)
          myTmpFh.Write myPem
          myTmpFh.Close
          myCmd = myOpenssl & " x509 -md5 -fingerprint -text -inform PEM" & _
                  " -in " & myTmpIn & " -out " & myTmpOut
          myRval = objShell.Run (myCmd, 0, TRUE)
          objFSO.DeleteFile myTmpIn, TRUE
          If Not (myRval = 0) Then
            MsgBox("Failed to process PEM cert with OpenSSL commandline!"), vbCritical, mySelf
            objFSO.DeleteFile myTmpOut, TRUE
            WScript.Quit 3
          End If
          Set myTmpFh = objFSO.OpenTextFile(myTmpOut, 1)
          myFh.Write myTmpFh.ReadAll & vbLf
          myTmpFh.Close
          objFSO.DeleteFile myTmpOut, TRUE
        End If
        myNumCerts = myNumCerts + 1
      End If
    Else
      myOctets = Split(myLines(i), "\")
      For j = 1 To UBound(myOctets)
        myData = myData & Chr(CByte("&o" & myOctets(j)))
      Next
    End If
  End If
  If InstrRev(myLines(i), "CVS_ID ") Then
    myPattern = "^CVS_ID\s+""(.+?)"""
    myRev = RegExprFirst(myPattern, myLines(i))
    myFh.Write "# " & myRev & vbLf & vbLf
  End If
  If InstrRev(myLines(i), "CKA_VALUE MULTILINE_OCTAL") Then
    myInsideCert = TRUE
    myUntrusted = FALSE
    myData = ""
  End If
  If InstrRev(myLines(i), "***** BEGIN LICENSE BLOCK *****") Then
    myInsideLicense = TRUE
  End If
  If (myInsideLicense = TRUE) Then
    myFh.Write myLines(i) & vbLf
    myLicenseText = myLicenseText & Mid(myLines(i), 2) & vbLf
  End If
  If InstrRev(myLines(i), "***** END LICENSE BLOCK *****") Then
    myInsideLicense = FALSE
    If (myAskLiF = TRUE) Then
      If Not (6 = objShell.PopUp(myLicenseText & vbLf & _
              "Do you agree to the license shown above (required to proceed) ?",, _
              mySelf, vbQuestion + vbYesNo + vbDefaultButton1)) Then
        myFh.Close
        objFSO.DeleteFile myCaFile, TRUE
        WScript.Quit 2
      End If
    End If
  End If
Next
myFh.Close
objShell.PopUp "Done (" & myNumCerts & " CA certs processed, " & myNumSkipped & _
               " untrusted skipped).", 20, mySelf, vbInformation
WScript.Quit 0

Function ConvertBinaryData(arrBytes)
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.Open
  objStream.Type = 1
  objStream.Write arrBytes
  objStream.Position = 0
  objStream.Type = 2
  objStream.Charset = "ascii"
  ConvertBinaryData = objStream.ReadText
  Set objStream = Nothing
End Function

Function RegExprFirst(SearchPattern, TheString)
  Dim objRegExp, Matches                        ' create variables.
  Set objRegExp = New RegExp                    ' create a regular expression.
  objRegExp.Pattern = SearchPattern             ' sets the search pattern.
  objRegExp.IgnoreCase = TRUE                   ' set to ignores case.
  objRegExp.Global = TRUE                       ' set to gloabal search.
  Set Matches = objRegExp.Execute(TheString)    ' do the search.
  If (Matches.Count) Then
    RegExprFirst = Matches(0).SubMatches(0)     ' return first match.
  Else
    RegExprFirst = ""
  End If
  Set objRegExp = Nothing
End Function

Function Base64Encode(inData)
  Const Base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  Dim cOut, sOut, lWrap, I
  lWrap = Int(myWrapLe * 3 / 4)

  'For each group of 3 bytes
  For I = 1 To Len(inData) Step 3
    Dim nGroup, pOut, sGroup

    'Create one long from this 3 bytes.
    nGroup = &H10000 * Asc(Mid(inData, I, 1)) + _
             &H100 * MyASC(Mid(inData, I + 1, 1)) + _
             MyASC(Mid(inData, I + 2, 1))

    'Oct splits the long To 8 groups with 3 bits
    nGroup = Oct(nGroup)

    'Add leading zeros
    nGroup = String(8 - Len(nGroup), "0") & nGroup

    'Convert To base64
    pOut = Mid(Base64, CLng("&o" & Mid(nGroup, 1, 2)) + 1, 1) & _
           Mid(Base64, CLng("&o" & Mid(nGroup, 3, 2)) + 1, 1) & _
           Mid(Base64, CLng("&o" & Mid(nGroup, 5, 2)) + 1, 1) & _
           Mid(Base64, CLng("&o" & Mid(nGroup, 7, 2)) + 1, 1)

    'Add the part To OutPut string
    sOut = sOut + pOut

    'Add a new line For Each myWrapLe chars In dest
    If (I < Len(inData) - 2) Then
      If (I + 2) Mod lWrap = 0 Then sOut = sOut & vbLf
    End If
  Next
  Select Case Len(inData) Mod 3
    Case 1: '8 bit final
      sOut = Left(sOut, Len(sOut) - 2) & "=="
    Case 2: '16 bit final
      sOut = Left(sOut, Len(sOut) - 1) & "="
  End Select
  Base64Encode = sOut
End Function

Function MyASC(OneChar)
  If OneChar = "" Then MyASC = 0 Else MyASC = Asc(OneChar)
End Function


