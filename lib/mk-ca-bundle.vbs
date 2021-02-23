'***************************************************************************
'*                                  _   _ ____  _
'*  Project                     ___| | | |  _ \| |
'*                             / __| | | | |_) | |
'*                            | (__| |_| |  _ <| |___
'*                             \___|\___/|_| \_\_____|
'*
'* Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
'*
'* This software is licensed as described in the file COPYING, which
'* you should have received as part of this distribution. The terms
'* are also available at https://curl.se/docs/copyright.html.
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
Const myVersion = "0.4.0"

Const myUrl = "https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt"

Const myOpenSSL = "openssl.exe"
Dim myUseOpenSSL
myUseOpenSSL = TRUE          ' Flag: TRUE to use OpenSSL. If TRUE and is not
                             ' found then a warning is shown before continuing.

Const myCdSavF = TRUE        ' Flag: save downloaded data to file certdata.txt
Const myCaBakF = TRUE        ' Flag: backup existing ca-bundle certificate
Const myAskLiF = TRUE        ' Flag: display certdata.txt license agreement
Const myWrapLe = 76          ' Default length of base64 output lines

' cert info code doesn't work properly with any recent openssl, leave disabled.
' Also: we want our certificate output by default to be as similar as possible
' to mk-ca-bundle.pl and setting this TRUE changes the base64 width to
' OpenSSL's built-in default width, which is not the same as mk-ca-bundle.pl.
Const myAskTiF = FALSE       ' Flag: ask to include certificate text info

'
'******************* Nothing to configure below! *******************
'
Const adTypeBinary = 1
Const adTypeText = 2
Const adSaveCreateNotExist = 1
Const adSaveCreateOverWrite = 2
Dim objShell, objNetwork, objFSO, objHttp
Dim myBase, mySelf, myStream, myTmpFh, myCdData, myCdFile
Dim myCaFile, myTmpName, myBakNum, myOptTxt, i
Set objNetwork = WScript.CreateObject("WScript.Network")
Set objShell = WScript.CreateObject("WScript.Shell")
Set objFSO = WScript.CreateObject("Scripting.FileSystemObject")
Set objHttp = WScript.CreateObject("WinHttp.WinHttpRequest.5.1")
If objHttp Is Nothing Then Set objHttp = WScript.CreateObject("WinHttp.WinHttpRequest")
myBase = Left(WScript.ScriptFullName, InstrRev(WScript.ScriptFullName, "\"))
mySelf = Left(WScript.ScriptName, InstrRev(WScript.ScriptName, ".") - 1) & " " & myVersion

myCdFile = Mid(myUrl, InstrRev(myUrl, "/") + 1)
myCaFile = "ca-bundle.crt"
myTmpName = InputBox("It will take a minute to download and parse the " & _
                     "certificate data." & _
                     vbLf & vbLf & _
                     "Please enter the output filename:", mySelf, myCaFile)
If (myTmpName = "") Then
  WScript.Quit 1
End If
myCaFile = myTmpName
If (myCdFile = "") Then
  MsgBox("URL does not contain filename!"), vbCritical, mySelf
  WScript.Quit 1
End If

' Don't use OpenSSL if it's not present.
If (myUseOpenSSL = TRUE) Then
  Dim errnum

  On Error Resume Next
  Call objShell.Run("""" & myOpenSSL & """ version", 0, TRUE)
  errnum = Err.Number
  On Error GoTo 0

  If Not (errnum = 0) Then
    myUseOpenSSL = FALSE
    MsgBox("OpenSSL was not found so the certificate bundle will not " & _
           "include the SHA256 hash of the raw certificate data file " & _
           "that was used to generate the certificates in the bundle. " & _
           vbLf & vbLf & _
           "This does not have any effect on the certificate output, " & _
           "so this script will continue." & _
           vbLf & vbLf & _
           "If you want to set a custom location for OpenSSL or disable " & _
           "this message then edit the variables at the start of the " & _
           "script."), vbInformation, mySelf
  End If
End If

If (myAskTiF = TRUE) And (myUseOpenSSL = TRUE) Then
  If (6 = objShell.PopUp("Do you want to include text information about " & _
                         "each certificate?" & vbLf & _
                         "(Requires OpenSSL.exe in the current directory " & _
                         "or search path)",, _
          mySelf, vbQuestion + vbYesNo + vbDefaultButton2)) Then
    myOptTxt = TRUE
  Else
    myOptTxt = FALSE
  End If
End If

' Uncomment the line below to ignore SSL invalid cert errors
' objHttp.Option(4) = 256 + 512 + 4096 + 8192
objHttp.SetTimeouts 0, 5000, 10000, 10000
objHttp.Open "GET", myUrl, FALSE
objHttp.setRequestHeader "User-Agent", WScript.ScriptName & "/" & myVersion
objHttp.Send ""
If Not (objHttp.Status = 200) Then
  MsgBox("Failed to download '" & myCdFile & "': " & objHttp.Status & " - " & objHttp.StatusText), vbCritical, mySelf
  WScript.Quit 1
End If
' Write received data to file if enabled
If (myCdSavF = TRUE) Then
  Call SaveBinaryData(myCdFile, objHttp.ResponseBody)
End If
' Convert data from ResponseBody instead of using ResponseText because of UTF-8
myCdData = ConvertBinaryToUTF8(objHttp.ResponseBody)
Set objHttp = Nothing
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

' Process the received data
Dim myLines, myPattern, myInsideCert, myInsideLicense, myLicenseText, myNumCerts, myNumSkipped
Dim myLabel, myOctets, myData, myPem, myRev, myUntrusted, j
myNumSkipped = 0
myNumCerts = 0
myData = ""
myLines = Split(myCdData, vbLf, -1)
Set myStream = CreateObject("ADODB.Stream")
myStream.Open
myStream.Type = adTypeText
myStream.Charset = "utf-8"
myStream.WriteText "##" & vbLf & _
  "## Bundle of CA Root Certificates" & vbLf & _
  "##" & vbLf & _
  "## Certificate data from Mozilla as of: " & _
    ConvertDateToString(LocalDateToUTC(Now)) & " GMT" & vbLf & _
  "##" & vbLf & _
  "## This is a bundle of X.509 certificates of public Certificate Authorities" & vbLf & _
  "## (CA). These were automatically extracted from Mozilla's root certificates" & vbLf & _
  "## file (certdata.txt).  This file can be found in the mozilla source tree:" & vbLf & _
  "## " & myUrl & vbLf & _
  "##" & vbLf & _
  "## It contains the certificates in PEM format and therefore" & vbLf & _
  "## can be directly used with curl / libcurl / php_curl, or with" & vbLf & _
  "## an Apache+mod_ssl webserver for SSL client authentication." & vbLf & _
  "## Just configure this file as the SSLCACertificateFile." & vbLf & _
  "##" & vbLf & _
  "## Conversion done with mk-ca-bundle.vbs version " & myVersion & "." & vbLf
If (myCdSavF = TRUE) And (myUseOpenSSL = TRUE) Then
  myStream.WriteText "## SHA256: " & FileSHA256(myCdFile) & vbLf
End If
myStream.WriteText "##" & vbLf & vbLf

myStream.WriteText vbLf
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
        If InstrRev(myLines(i), "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR") Then
          myUntrusted = FALSE
        End If
      Wend
      If (myUntrusted = TRUE) Then
        myNumSkipped = myNumSkipped + 1
      Else
        myStream.WriteText myLabel & vbLf
        myStream.WriteText String(Len(myLabel), "=") & vbLf
        myPem = "-----BEGIN CERTIFICATE-----" & vbLf & _
                Base64Encode(myData) & vbLf & _
                "-----END CERTIFICATE-----" & vbLf
        If (myOptTxt = FALSE) Then
          myStream.WriteText myPem & vbLf
        Else
          Dim myCmd, myRval, myTmpIn, myTmpOut
          myTmpIn = objFSO.GetSpecialFolder(2).Path & "\" & objFSO.GetTempName
          myTmpOut = objFSO.GetSpecialFolder(2).Path & "\" & objFSO.GetTempName
          Set myTmpFh = objFSO.OpenTextFile(myTmpIn, 2, TRUE)
          myTmpFh.Write myPem
          myTmpFh.Close
          myCmd = """" & myOpenSSL & """ x509 -md5 -fingerprint -text " & _
                  "-inform PEM -in " & myTmpIn & " -out " & myTmpOut
          myRval = objShell.Run (myCmd, 0, TRUE)
          objFSO.DeleteFile myTmpIn, TRUE
          If Not (myRval = 0) Then
            MsgBox("Failed to process PEM cert with OpenSSL commandline!"), vbCritical, mySelf
            objFSO.DeleteFile myTmpOut, TRUE
            WScript.Quit 3
          End If
          Set myTmpFh = objFSO.OpenTextFile(myTmpOut, 1)
          myStream.WriteText myTmpFh.ReadAll & vbLf
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
    myStream.WriteText "# " & myRev & vbLf & vbLf
  End If
  If InstrRev(myLines(i), "CKA_VALUE MULTILINE_OCTAL") Then
    myInsideCert = TRUE
    myUntrusted = TRUE
    myData = ""
  End If
  If InstrRev(myLines(i), "***** BEGIN LICENSE BLOCK *****") Then
    myInsideLicense = TRUE
  End If
  If (myInsideLicense = TRUE) Then
    myStream.WriteText myLines(i) & vbLf
    myLicenseText = myLicenseText & Mid(myLines(i), 2) & vbLf
  End If
  If InstrRev(myLines(i), "***** END LICENSE BLOCK *****") Then
    myInsideLicense = FALSE
    If (myAskLiF = TRUE) Then
      If Not (6 = objShell.PopUp(myLicenseText & vbLf & _
              "Do you agree to the license shown above (required to proceed) ?",, _
              mySelf, vbQuestion + vbYesNo + vbDefaultButton1)) Then
        myStream.Close
        objFSO.DeleteFile myCaFile, TRUE
        WScript.Quit 2
      End If
    End If
  End If
Next

' To stop the UTF-8 BOM from being written the stream has to be copied and
' then saved as binary.
Dim myCopy
Set myCopy = CreateObject("ADODB.Stream")
myCopy.Type = adTypeBinary
myCopy.Open
myStream.Position = 3 ' Skip UTF-8 BOM
myStream.CopyTo myCopy
myCopy.SaveToFile myCaFile, adSaveCreateOverWrite
myCopy.Close
myStream.Close
Set myCopy = Nothing
Set myStream = Nothing

' Done
objShell.PopUp "Done (" & myNumCerts & " CA certs processed, " & myNumSkipped & _
               " untrusted skipped).", 20, mySelf, vbInformation
WScript.Quit 0

Function ConvertBinaryToUTF8(arrBytes)
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.Open
  objStream.Type = adTypeBinary
  objStream.Write arrBytes
  objStream.Position = 0
  objStream.Type = adTypeText
  objStream.Charset = "utf-8"
  ConvertBinaryToUTF8 = objStream.ReadText
  Set objStream = Nothing
End Function

Function SaveBinaryData(filename, data)
  Dim objStream
  Set objStream = CreateObject("ADODB.Stream")
  objStream.Type = adTypeBinary
  objStream.Open
  objStream.Write data
  objStream.SaveToFile filename, adSaveCreateOverWrite
  objStream.Close
  Set objStream = Nothing
End Function

Function RegExprFirst(SearchPattern, TheString)
  Dim objRegExp, Matches                        ' create variables.
  Set objRegExp = New RegExp                    ' create a regular expression.
  objRegExp.Pattern = SearchPattern             ' sets the search pattern.
  objRegExp.IgnoreCase = TRUE                   ' set to ignores case.
  objRegExp.Global = TRUE                       ' set to global search.
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

' Return the date in the same format as perl to match mk-ca-bundle.pl output:
' Wed Sep  7 03:12:05 2016
Function ConvertDateToString(input)
  Dim output
  output = WeekDayName(WeekDay(input), TRUE) & " " & _
           MonthName(Month(input), TRUE) & " "
  If (Len(Day(input)) = 1) Then
    output = output & " "
  End If
  output = output & _
           Day(input) & " " & _
           FormatDateTime(input, vbShortTime) & ":"
  If (Len(Second(input)) = 1) Then
    output = output & "0"
  End If
  output = output & _
           Second(input) & " " & _
           Year(input)
  ConvertDateToString = output
End Function

' Convert local Date to UTC. Microsoft says:
' Use Win32_ComputerSystem CurrentTimeZone property, because it automatically
' adjusts the Time Zone bias for daylight saving time; Win32_Time Zone Bias
' property does not.
' https://msdn.microsoft.com/en-us/library/windows/desktop/ms696015.aspx
Function LocalDateToUTC(localdate)
  Dim item, offset
  For Each item In GetObject("winmgmts:").InstancesOf("Win32_ComputerSystem")
    offset = item.CurrentTimeZone ' the offset in minutes
  Next
  If (offset < 0) Then
    LocalDateToUTC = DateAdd("n",  ABS(offset), localdate)
  Else
    LocalDateToUTC = DateAdd("n", -ABS(offset), localdate)
  End If
  'objShell.PopUp LocalDateToUTC
End Function

Function FileSHA256(filename)
  Dim cmd, rval, tmpOut, tmpFh
  if (myUseOpenSSL = TRUE) Then
    tmpOut = objFSO.GetSpecialFolder(2).Path & "\" & objFSO.GetTempName
    cmd = """" & myOpenSSL & """ dgst -r -sha256 -out """ & tmpOut & """ """ & filename & """"
    rval = objShell.Run(cmd, 0, TRUE)
    If Not (rval = 0) Then
      MsgBox("Failed to get sha256 of """ & filename & """ with OpenSSL commandline!"), vbCritical, mySelf
      objFSO.DeleteFile tmpOut, TRUE
      WScript.Quit 3
    End If
    Set tmpFh = objFSO.OpenTextFile(tmpOut, 1)
    FileSHA256 = RegExprFirst("^([0-9a-f]{64}) .+", tmpFh.ReadAll)
    tmpFh.Close
    objFSO.DeleteFile tmpOut, TRUE
  Else
    FileSHA256 = ""
  End If
End Function
