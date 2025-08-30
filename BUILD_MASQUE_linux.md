# setup cURL with MASQUE<br>
## create install directories<br>
mkdir install<br>
cd install<br>
mkdir install-openssl<br>
mkdir install-nghttp3<br>
mkdir install-curl<br>
cd ../<br>
## build openssl<br>
git clone https://github.com/openssl/openssl<br>
cd openssl/<br>
./config enable-tls1_3 --prefix="path to install-openssl --libdir=lib64<br>
  OR (to enable max level of debugging in openssl)<br>
./config -d shared -g3 -ggdb -gdwarf-4 -fno-inline -O0 -DDEBUG_SAFESTACK enable-tls1_3 --prefix="path to install-openssl" --libdir=lib64<br>
sudo make<br>
sudo make install<br>
cd ../<br>
## build nghttp3<br>
sudo apt install libnghttp3-dev<br>
git clone https://github.com/ngtcp2/nghttp3<br>
cd nghttp3/<br>
git submodule update --init<br>
autoreconf -fi<br>
./configure --prefix="path to install-nghttp3" --enable-lib-only<br>
  OR (to enable debug)<br>
./configure --prefix="path to install-nghttp3" --enable-lib-only --enable-debug<br>
sudo make<br>
sudo make install<br>
cd ../<br>
## build cURL (with MASQUE support)<br>
git clone https://github.com/aritrbas/curl.git<br>
cd curl<br>
git checkout adding-masque-support-new<br>
autoreconf -fi<br>
LDFLAGS="-Wl,-rpath,"path to install-openssl"/lib64 ./configure --prefix="path to install-curl" --with-openssl="path to install-openssl" --with-openssl-quic --with-nghttp3="path to install-nghttp3" --enable-debug<br>
sudo make<br>
sudo make install<br>
cd ../<br>
<br>
<br>
# test setup<br>
## setup h2o server<br>
sudo apt install cmake make gcc libyaml-dev libssl-dev<br>
git clone https://github.com/h2o/h2o.git<br>
cd h2o<br>
mkdir build<br>
cd build<br>
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-DH2O_LOGGING=1' ..<br>
sudo make<br>
sudo make install<br>
h2o --version<br>
## setup envoy proxy server<br>
wget -O- https://apt.envoyproxy.io/signing.key | sudo gpg --dearmor -o /etc/apt/keyrings/envoy-keyring.gpg<br>
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/envoy-keyring.gpg] https://apt.envoyproxy.io jammy main" | sudo tee /etc/apt/sources.list.d/envoy.list<br>
sudo apt-get update<br>
sudo apt-get install envoy<br>
envoy --version<br>