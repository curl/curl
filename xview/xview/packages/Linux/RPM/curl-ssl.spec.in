%define name curl-ssl
%define tarball curl
%define version 7.11.0
%define release 1

%define curlroot %{_builddir}/%{tarball}-%{version}

Summary: get a file from an FTP or HTTP server.
Name: %{name}
Version: %{version}
Release: %{release}
Copyright: MIT/X derivate
Vendor: Daniel Stenberg <Daniel.Stenberg@haxx.se>
Packager: Troy Engel <tengel@sonic.net>
Group: Utilities/Console
Source: %{tarball}-%{version}.tar.gz
URL: https://curl.haxx.se/
Provides: curl
Obsoletes: curl
BuildRoot: %{_tmppath}/%{tarball}-%{version}-root
Requires: openssl >= 0.9.5

%description
curl is a client to get documents/files from servers, using any of the
supported protocols. The command is designed to work without user
interaction or any kind of interactivity.

curl offers a busload of useful tricks like proxy support, user
authentication, ftp upload, HTTP post, file transfer resume and more.

%package	devel
Summary:	The includes, libs, and man pages to develop with libcurl
Group:		Development/Libraries
Requires:	openssl-devel >= 0.9.5
Provides:	curl-devel

%description devel
libcurl is the core engine of curl; this packages contains all the libs,
headers, and manual pages to develop applications using libcurl.

%prep

%setup -q -n %{tarball}-%{version}

%build
cd %{curlroot} && (if [ -f configure.in ]; then mv -f configure.in configure.in.rpm; fi)
%configure
cd %{curlroot} && (if [ -f configure.in.rpm ]; then mv -f configure.in.rpm configure.in; fi)
make

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
make DESTDIR=%{buildroot} install-strip

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
[ "%{curlroot}" != "/" ] && rm -rf %{curlroot}

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/curl
%attr(0644,root,root) %{_mandir}/man1/curl.1*
%attr(0644,root,root) %{_mandir}/man1/mk-ca-bundle.1
%{_libdir}/libcurl.so*
%{_datadir}/curl/curl-ca-bundle.crt
%doc CHANGES COPYING README testcurl.sh docs/BUGS docs/SSLCERTS
%doc docs/CONTRIBUTE docs/FAQ docs/FEATURES docs/HISTORY docs/INSTALL
%doc docs/KNOWN_BUGS docs/MANUAL docs/RESOURCES docs/THANKS
%doc docs/TODO docs/VERSIONS docs/TheArtOfHttpScripting tests

%files devel
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/curl-config
%attr(0644,root,root) %{_mandir}/man1/curl-config.1*
%attr(0644,root,root) %{_mandir}/man3/*
%attr(0644,root,root) %{_includedir}/curl/*
%{_libdir}/libcurl.a
%{_libdir}/libcurl.la
%doc docs/BINDINGS docs/INTERNALS docs/examples/* docs/libcurl-the-guide
