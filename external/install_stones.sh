#!/bin/bash
CAPSTONE="capstone-3.0.4"
KEYSTONE="keystone-0.9.1"
PYTHON_PATH="/usr/lib/python2.7" 
CURRENT=`pwd`

tar -xzvf $CAPSTONE.tar.gz
tar -xzvf $KEYSTONE.tar.gz

#Install Capstone
cd capstone-3.0.4 && ./make.sh && make install
cp -r bindings/capstone $PYTHON_PATH
cd ..

#Install Keystone
apt-get -y install cmake
cd $KEYSTONE
mkdir build && cd build
../make-share.sh
cp kstool/kstool /bin
cd ../bindings/python && make install
cp ../../build/llvm/lib/libkeystone.so /lib

# Clean up
cd $CURRENT
rm $CAPSTONE.tar.gz
rm $KEYSTONE.tar.gz


