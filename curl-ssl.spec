%define name curl-ssl
%define tarball curl
%define version 6.5.2
%define release 1
%define prefix /usr/local

%define builddir $RPM_BUILD_DIR/%{tarball}-%{version}

Summary: get a file from a FTP, GOPHER or HTTP server.
Name: %{name}
Version: %{version}
Release: %{release}
Copyright: MPL
Vendor: Daniel Stenberg <Daniel.Stenberg@haxx.nu>
Packager: Troy Engel <tengel@sonic.net>
Group: Utilities/Console
Source: %{tarball}-%{version}.tar.gz
URL: http://curl.haxx.nu/
BuildRoot: /tmp/%{tarball}-%{version}-root

%description
curl is a client to get documents/files from servers, using any of the
supported protocols. The command is designed to work without user
interaction or any kind of interactivity.

curl offers a busload of useful tricks like proxy support, user
authentication, ftp upload, HTTP post, file transfer resume and more.

Note: this version is compiled with SSL (https:) support.

%prep
rm -rf $RPM_BUILD_ROOT
rm -rf %{builddir}

%setup -n %{tarball}-%{version} 

%build
CFLAGS=$RPM_OPT_FLAGS ./configure --prefix=$RPM_BUILD_ROOT%{prefix}
make

%install
make install-strip
install -m 0644 curl.1 $RPM_BUILD_ROOT%{prefix}/man/man1

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf %{builddir}

%files
%defattr(-,root,root)
%attr(0755,root,root) %{prefix}/bin/curl
%attr(0644,root,root) %{prefix}/man/man1/curl.1
%doc BUGS CHANGES CONTRIBUTE FAQ FEATURES FILES INSTALL LEGAL MPL-1.0.txt README* RESOURCES TODO

