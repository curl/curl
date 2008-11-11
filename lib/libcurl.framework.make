# to build Mac OS X framework call the following line with the directory set
# properly to lib:
# make build -e -f libcurl.framework.make
TMP_DIR = ../lib/.lib
LIB_DIR = ../lib

# Sets the SDK. 10.4u.sdk is the minimum for building a Universal Binary.
SDK = /Developer/SDKs/MacOSX10.4u.sdk

# Sets the minimum OSX version where the framework will work.
ENVP = MACOSX_DEPLOYMENT_TARGET=10.3

# for debug symbols add the -g option.  Remove the -O2 option for best debugging.
# Can be compiled with -O3 optimizations.
C_OPTIONS = -isysroot $(SDK) \
	-fno-common \
	-Os \
	-DHAVE_CONFIG_H \
	-DPIC \
	-I../lib \
	-I../include \
	-Wall \
	-arch ppc \
	-arch i386

LIBRARIES = $(SDK)/usr/lib/libssl.dylib \
	$(SDK)/usr/lib/libcrypto.dylib \
	-lz 

# These libtool options are needed for a framework.
# @executable_path tells the application that links to this library where to find it.
# On Mac OS X frameworks are usually iniside the application bundle in a frameworks folder.
# Define a seg1addr so prebinding does not overlap with other frameworks or bundles.
# For prebinding 0x10400000 was chosen a bit at random.  
# If this overlaps one of you current libs just change in the makefile. 
# This address is safe for all built in frameworks.  
LINK_OPTIONS = \
	-Wl,-syslibroot,$(SDK) \
	-arch ppc \
	-arch i386 \
	-prebind \
	-seg1addr 0x10400000 \
	-dynamiclib \
	-install_name @executable_path/../Frameworks/libcurl.framework/libcurl

# This is the file list.  It is not dynamically generated so this must be updated if new files are added to the build.
OBJECTS = $(TMP_DIR)/base64.o \
	$(TMP_DIR)/connect.o \
	$(TMP_DIR)/content_encoding.o \
	$(TMP_DIR)/cookie.o \
	$(TMP_DIR)/curl_addrinfo.o \
	$(TMP_DIR)/dict.o \
	$(TMP_DIR)/easy.o \
	$(TMP_DIR)/escape.o \
	$(TMP_DIR)/file.o \
	$(TMP_DIR)/formdata.o \
	$(TMP_DIR)/ftp.o \
	$(TMP_DIR)/getenv.o \
	$(TMP_DIR)/getinfo.o \
	$(TMP_DIR)/gtls.o \
	$(TMP_DIR)/hash.o \
	$(TMP_DIR)/hostares.o \
	$(TMP_DIR)/hostasyn.o \
	$(TMP_DIR)/hostip.o \
	$(TMP_DIR)/hostip4.o \
	$(TMP_DIR)/hostip6.o \
	$(TMP_DIR)/hostsyn.o \
	$(TMP_DIR)/hostthre.o \
	$(TMP_DIR)/http.o \
	$(TMP_DIR)/http_chunks.o \
	$(TMP_DIR)/http_digest.o \
	$(TMP_DIR)/http_negotiate.o \
	$(TMP_DIR)/http_ntlm.o \
	$(TMP_DIR)/if2ip.o \
	$(TMP_DIR)/inet_ntop.o \
	$(TMP_DIR)/inet_pton.o \
	$(TMP_DIR)/krb4.o \
	$(TMP_DIR)/ldap.o \
	$(TMP_DIR)/llist.o \
	$(TMP_DIR)/md5.o \
	$(TMP_DIR)/memdebug.o \
	$(TMP_DIR)/mprintf.o \
	$(TMP_DIR)/multi.o \
	$(TMP_DIR)/netrc.o \
	$(TMP_DIR)/parsedate.o \
	$(TMP_DIR)/progress.o \
	$(TMP_DIR)/rawstr.o \
	$(TMP_DIR)/security.o \
	$(TMP_DIR)/select.o \
	$(TMP_DIR)/sendf.o \
	$(TMP_DIR)/share.o \
	$(TMP_DIR)/speedcheck.o \
	$(TMP_DIR)/sslgen.o \
	$(TMP_DIR)/ssluse.o \
	$(TMP_DIR)/strequal.o \
	$(TMP_DIR)/strerror.o \
	$(TMP_DIR)/strtok.o \
	$(TMP_DIR)/strtoofft.o \
	$(TMP_DIR)/telnet.o \
	$(TMP_DIR)/tftp.o \
	$(TMP_DIR)/timeval.o \
	$(TMP_DIR)/transfer.o \
	$(TMP_DIR)/url.o \
	$(TMP_DIR)/version.o \
	$(TMP_DIR)/splay.o \
	$(TMP_DIR)/socks.o 

build: $(TMP_DIR) $(LIB_DIR) $(LIB_DIR)/libcurl.framework

$(TMP_DIR) :
	mkdir -p $(TMP_DIR)

$(LIB_DIR) :
	mkdir -p $(LIB_DIR)
	
# This builds the framework structure and links everything properly	
$(LIB_DIR)/libcurl.framework: $(OBJECTS) $(LIB_DIR)/libcurl.plist
	mkdir -p $(LIB_DIR)/libcurl.framework/Versions/A/Resources
	 $(ENVP) $(CC) $(LINK_OPTIONS) $(LIBRARIES) $(OBJECTS) \
		-o $(LIB_DIR)/libcurl.framework/Versions/A/libcurl
	cp $(LIB_DIR)/libcurl.plist $(LIB_DIR)/libcurl.framework/Versions/A/Resources/Info.plist
	mkdir -p $(LIB_DIR)/libcurl.framework/Versions/A/Headers
	cp $(LIB_DIR)/../include/curl/*.h $(LIB_DIR)/libcurl.framework/Versions/A/Headers
	cd $(LIB_DIR)/libcurl.framework; \
	   ln -fs Versions/A/libcurl libcurl; \
	   ln -fs Versions/A/Resources Resources; \
	   ln -fs Versions/A/Headers Headers
	cd $(LIB_DIR)/libcurl.framework/Versions; \
	   ln -fs A Current

$(OBJECTS) : $(TMP_DIR)/%.o: $(LIB_DIR)/%.c 
	$(CC) $(C_OPTIONS) -c $< -o $@

clean:
	rm -fr $(LIB_DIR)/libcurl.framework
	rm -f $(OBJECTS)



