TMP_DIR = ../lib/.lib
LIB_DIR = ../lib

# for debug symbols add the -g option.  Remove the -O2 option for best debuggin.
# Can be compiled with -O3 optimizations.
C_OPTIONS = \
	-fno-common \
	-O2 \
	-DHAVE_CONFIG_H \
	-DPIC \
	-I../lib \
	-I../include \
	-Wall

# The 2 -framework tags are the needed Mac OS X sytem libs
# must link to version 0.9 of libssl to run on Mac OS X 10.2.  10.1 is not tested but should work.
LIBRARIES = -framework CoreFoundation \
	-framework CoreServices \
	/usr/lib/libssl.dylib \
	/usr/lib/libcrypto.dylib \
	-lz 

# These libtool options are needed for a framework.
# @executable_path tells the application that links to this library where to find it.
# On Mac OS X frameworks are usually iniside the application bundle in a frameworks folder.
# Define a seg1addr so prebinding does not overlap with other frameworks or bundles.
# For prebinding 0x10400000 was chosen a bit at random.  
# If this overlaps one of you current libs just change in the makefile. 
# This address is safe for all built in frameworks.  
LINK_OPTIONS = -prebind \
	-seg1addr 0x10400000 \
	-dynamiclib \
	-install_name @executable_path/../frameworks/libcurl.framework/libcurl

# This is the file list.  It is not dynamically generated so this must be updated if new files are added to the build.
OBJECTS = $(TMP_DIR)/base64.o \
	$(TMP_DIR)/connect.o \
	$(TMP_DIR)/content_encoding.o \
	$(TMP_DIR)/cookie.o \
	$(TMP_DIR)/dict.o \
	$(TMP_DIR)/easy.o \
	$(TMP_DIR)/escape.o \
	$(TMP_DIR)/file.o \
	$(TMP_DIR)/formdata.o \
	$(TMP_DIR)/ftp.o \
	$(TMP_DIR)/getdate.o \
	$(TMP_DIR)/getenv.o \
	$(TMP_DIR)/getinfo.o \
	$(TMP_DIR)/hash.o \
	$(TMP_DIR)/hostip.o \
	$(TMP_DIR)/http.o \
	$(TMP_DIR)/http_chunks.o \
	$(TMP_DIR)/http_digest.o \
	$(TMP_DIR)/http_negotiate.o \
	$(TMP_DIR)/http_ntlm.o \
	$(TMP_DIR)/if2ip.o \
	$(TMP_DIR)/inet_pton.o \
	$(TMP_DIR)/krb4.o \
	$(TMP_DIR)/ldap.o \
	$(TMP_DIR)/llist.o \
	$(TMP_DIR)/md5.o \
	$(TMP_DIR)/memdebug.o \
	$(TMP_DIR)/mprintf.o \
	$(TMP_DIR)/multi.o \
	$(TMP_DIR)/netrc.o \
	$(TMP_DIR)/progress.o \
	$(TMP_DIR)/security.o \
	$(TMP_DIR)/sendf.o \
	$(TMP_DIR)/share.o \
	$(TMP_DIR)/speedcheck.o \
	$(TMP_DIR)/ssluse.o \
	$(TMP_DIR)/strequal.o \
	$(TMP_DIR)/strtok.o \
	$(TMP_DIR)/telnet.o \
	$(TMP_DIR)/timeval.o \
	$(TMP_DIR)/transfer.o \
	$(TMP_DIR)/url.o \
	$(TMP_DIR)/version.o 

build: $(TMP_DIR) $(LIB_DIR) $(LIB_DIR)/libcurl.framework

$(TMP_DIR) :
	mkdir -p $(TMP_DIR)

$(LIB_DIR) :
	mkdir -p $(LIB_DIR)
	
# This builds the framework structure and links everything properly	
$(LIB_DIR)/libcurl.framework: $(OBJECTS) $(LIB_DIR)/libcurl.plist
	mkdir -p $(LIB_DIR)/libcurl.framework/Versions/A/Resources
	$(CC) $(LINK_OPTIONS) $(LIBRARIES) $(OBJECTS) \
		-o $(LIB_DIR)/libcurl.framework/Versions/A/libcurl
	cp $(LIB_DIR)/libcurl.plist $(LIB_DIR)/libcurl.framework/Versions/A/Resources/Info.plist
	cd $(LIB_DIR)/libcurl.framework; \
	ln -fs ./Versions/A/libcurl libcurl; \
	ln -fs ./Versions/A/Resources Resources
	cd $(LIB_DIR)/libcurl.framework/Versions; \
	ln -fs ./A Current

$(OBJECTS) : $(TMP_DIR)/%.o: $(LIB_DIR)/%.c 
	$(CC) $(C_OPTIONS) -c $< -o $@

clean:
	rm -fr $(LIB_DIR)/libcurl.framework
	rm -f $(OBJECTS)



