#!/bin/sh
#
# Copyright (c) 2023 Yoichi Tanibayashi
#

ADDR=$1
OUTFILE=/tmp/$0.out
WORKFILE=$OUTFILE.work
SUDO=sudo
#NMAP_OPTS="--scan-delay 500ms"
NMAP_OPTS=""

while true; do
    $SUDO nmap $NMAP_OPTS -sP -oX $WORKFILE $ADDR > /dev/null 2>&1
    $SUDO mv -f $WORKFILE $OUTFILE
    date +'%Y-%m-%d %H:%M:%S'
    sleep 1
done
