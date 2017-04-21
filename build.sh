#!/bin/bash

make clean
./configure --with-libtrace && make
cp libpcap.so.1.7.4 libpcap.so
