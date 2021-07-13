Long: quote
Arg: <command>
Short: Q
Help: Send command(s) to server before transfer
Protocols: FTP SFTP
Category: ftp sftp
---

Send an arbitrary command to the remote FTP or SFTP server. Quote commands are
sent BEFORE the transfer takes place (just after the initial PWD command in an
FTP transfer, to be exact). To make commands take place after a successful
transfer, prefix them with a dash '-'.  To make commands be sent after curl
has changed the working directory, just before the transfer command(s), prefix
the command with a '+' (this is only supported for FTP). You may specify any
number of commands.

If the server returns failure for one of the commands, the entire operation
will be aborted. You must send syntactically correct FTP commands as RFC 959
defines to FTP servers, or one of the commands listed below to SFTP servers.

Prefix the command with an asterisk (*) to make curl continue even if the
command fails as by default curl will stop at first failure.

This option can be used multiple times.

SFTP is a binary protocol. Unlike for FTP, curl interprets SFTP quote commands
itself before sending them to the server.  File names may be quoted
shell-style to embed spaces or special characters.  Following is the list of
all supported SFTP quote commands:
.RS
.IP "atime date file"
The atime command sets the last access time of the file named by the file
operand. The <date expression> can be all sorts of date strings, see the
*curl_getdate(3)* man page for date expression details. (Added in 7.73.0)
.IP "chgrp group file"
The chgrp command sets the group ID of the file named by the file operand to
the group ID specified by the group operand. The group operand is a decimal
integer group ID.
.IP "chmod mode file"
The chmod command modifies the file mode bits of the specified file. The
mode operand is an octal integer mode number.
.IP "chown user file"
The chown command sets the owner of the file named by the file operand to the
user ID specified by the user operand. The user operand is a decimal
integer user ID.
.IP "ln source_file target_file"
The ln and symlink commands create a symbolic link at the target_file location
pointing to the source_file location.
.IP "mkdir directory_name"
The mkdir command creates the directory named by the directory_name operand.
.IP "mtime date file"
The mtime command sets the last modification time of the file named by the
file operand. The <date expression> can be all sorts of date strings, see the
*curl_getdate(3)* man page for date expression details. (Added in 7.73.0)
.IP "pwd"
The pwd command returns the absolute pathname of the current working directory.
.IP "rename source target"
The rename command renames the file or directory named by the source
operand to the destination path named by the target operand.
.IP "rm file"
The rm command removes the file specified by the file operand.
.IP "rmdir directory"
The rmdir command removes the directory entry specified by the directory
operand, provided it is empty.
.IP "symlink source_file target_file"
See ln.
.RE
