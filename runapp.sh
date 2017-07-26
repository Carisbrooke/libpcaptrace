#!/bin/bash

IFACE="enp3s0"

if [ $# -eq 1 ]; then
	IFACE=$1
fi

#make && sudo ldconfig $PWD

#export LIBPCAPTRACE_IFACE="enp3s0,odp:03:00.0"
export LIBPCAPTRACE_IFACE="enp3s0,kafka:k"

sudo ldconfig $PWD
if [ -e ptm ]; then
	rm ptm
fi
gcc ptm.c -o ptm -L./ -lpcap
sudo -E ./ptm $IFACE


# link with common libpcap
#gcc ptm.c -o ptm -lpcap
