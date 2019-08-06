#!/bin/bash

rm -rf build
mkdir build
cd build
cmake -DMEMDBG_INSTALL_DIR=/usr/local -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2s ..
make wsclient_test
./wsclient_test
cd ..
rm -rf build
