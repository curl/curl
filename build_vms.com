$!
$	def = "sys_users:[nbaggus.curl]"
$	set def 'def'
$	cc_qual = "/define=HAVE_CONFIG_H=1/include=(""../include/"",""../"")"
$	if p1 .eqs. "LISTING" then cc_qual = cc_qual + "/LIST/MACHINE"
$	if p1 .eqs. "DEBUG" then cc_qual = cc_qual + "/LIST/MACHINE/DEBUG"
$	msg_qual = ""
$	call build "[.lib]" "*.c"
$	call build "[.src]" "*.c"
$	call build "[.src]" "*.msg"
$	link /exe=curl.exe [.src]curl/lib/include=main,[.lib]curl/lib
$
$
$	goto Exit
$build:	subroutine
$	set noon
$	set default 'p1'
$	search = p2
$Loop:
$	file = f$search(search,1)
$	if file .eqs. "" then goto EndLoop
$		obj = f$search(f$parse(".OBJ;",file),2)
$		if (obj .nes. "") 
$		then
$			if (f$cvtime(f$file(file,"rdt")) .gts. f$cvtime(f$file(obj,"rdt")))
$			then
$				call compile 'file'
$				lib/object curl.OLB 'f$parse(".obj;",file)'
$			else
$!				write sys$output "File: ''file' is up to date"
$			endif
$		else
$!			write sys$output "Object for file: ''file' does not exist"
$			call compile 'file'
$			lib/object curl.OLB 'f$parse(".obj;",file)'
$		endif
$	goto Loop
$EndLoop:
$	purge
$	set def 'def'
$	endsubroutine	! Build
$
$compile:	subroutine
$	set noon
$	file = p1
$	qual = p2+p3+p4+p5+p6+p7+p8
$	typ = f$parse(file,,,"TYPE") - "."
$	cmd_c = "CC "+cc_qual
$	cmd_msg = "MESSAGE "+msg_qual
$	x = cmd_'typ' 
$	'x' 'file'
$	ENDSUBROUTINE	! Compile
$
$Exit:
$	exit
