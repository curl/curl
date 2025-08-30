# setup cURL with MASQUE (macOS)<br>
## create install directories<br>
mkdir install<br>
cd install<br>
mkdir install-openssl<br>
mkdir install-nghttp3<br>
mkdir install-curl<br>
cd ../<br>
## install dependencies<br>
brew install libtool<br>
brew install automake<br>
brew install autoconf<br>
brew install pkgconf<br>
brew install openssl<br>
brew install libssh2<br>
brew install c-ares<br>
brew install libnghttp2<br>
brew install libnghttp3<br>
brew install libpsl<br>
brew install libidn2<br>
brew install zlib<br>
## build openssl<br>
git clone https://github.com/openssl/openssl<br>
cd openssl/<br>
./config enable-tls1_3 --prefix=`<path to install-openssl>` --libdir=lib64<br>
  OR (to enable max level of debugging in openssl)<br>
./config -d shared -g3 -ggdb -gdwarf-4 -fno-inline -O0 -DDEBUG_SAFESTACK enable-tls1_3 --prefix=`<path to install-openssl>` --libdir=lib64<br>
make<br>
make install<br>
cd ../<br>
## build nghttp3<br>
git clone https://github.com/ngtcp2/nghttp3<br>
cd nghttp3/<br>
git submodule update --init<br>
autoreconf -fi<br>
./configure --prefix=`<path to install-nghttp3>` --enable-lib-only<br>
  OR (to enable debug)<br>
./configure --prefix=`<path to install-nghttp3>` --enable-lib-only --enable-debug<br>
make<br>
make install<br>
cd ../<br>
## build cURL (with MASQUE support)<br>
git clone https://github.com/aritrbas/curl.git<br>
cd curl<br>
git checkout adding-masque-support-new<br>
autoreconf -fi<br>
LDFLAGS="-Wl,-rpath,`<path to install-openssl>`/lib64" ./configure --prefix=`<path to install-curl>` --with-openssl=`<path to install-openssl>` --with-openssl-quic --with-nghttp3=`<path to install-nghttp3>` --enable-debug<br>
make<br>
make install<br>
cd ../<br>
<br>
<br>
# test setup<br>
## setup h2o server<br>
brew install h2o<br>
