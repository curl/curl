%define ver	7.4.2
%define rel	1
%define prefix	/usr

Summary:	get a file from a FTP, GOPHER or HTTP server.
Name:		curl
Version:	%ver
Release:	%rel
Copyright:	MPL
Group:		Utilities/Console
Source:		%{name}-%{version}.tar.gz
URL:		http://curl.haxx.se
BuildRoot:	/tmp/%{name}-%{version}-%{rel}-root
Packager:	Fill In As You Wish
Docdir:		%{prefix}/doc

%description
curl is a client to get documents/files from servers, using 
any of the supported protocols.  The command is designed to 
work without user interaction or any kind of interactivity.

curl offers a busload of useful tricks like proxy support, 
user authentication, ftp upload, HTTP post, file transfer 
resume and more.

Note: this version is compiled without SSL (https:) support.

Authors:
	Daniel Stenberg <daniel@haxx.se>


%prep
%setup -n %{name}-%{version}


%build
# Needed for snapshot releases.
if [ ! -f configure ]; then
	CONF="./autogen.sh"
else
	CONF="./configure"
fi

#
# Configuring the package
#
CFLAGS="${RPM_OPT_FLAGS}" ${CONF}	\
	--prefix=%{prefix}


[ "$SMP" != "" ] && JSMP = '"MAKE=make -k -j $SMP"'

make ${JSMP};


%install
[ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

make prefix=${RPM_BUILD_ROOT}%{prefix} install-strip

#
# Generating file lists and store them in file-lists
# Starting with the directory listings
#
find ${RPM_BUILD_ROOT}%{prefix}/{bin,lib,man} -type d | sed "s#^${RPM_BUILD_ROOT}#\%attr (-\,root\,root) \%dir #" > file-lists

#
# Then, the file listings
#
echo "%defattr (-, root, root)" >> file-lists
find ${RPM_BUILD_ROOT}%{prefix} -type f | sed -e "s#^${RPM_BUILD_ROOT}##g" >> file-lists


%clean
(cd ..; rm -rf %{name}-%{version} ${RPM_BUILD_ROOT})


%files -f file-lists
%defattr (-, root, root)
%doc BUGS
%doc CHANGES
%doc CONTRIBUTE
%doc FAQ
%doc FEATURES
%doc FILES
%doc INSTALL
%doc LEGAL
%doc MPL-1.0.txt
%doc README
%doc README.curl
%doc README.libcurl
%doc RESOURCES
%doc TODO
%doc %{name}-ssl.spec.in
%doc %{name}.spec.in

