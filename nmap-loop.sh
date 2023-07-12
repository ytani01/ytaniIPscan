#!/bin/sh
#
# Copyright (c) 2023 Yoichi Tanibayashi
#

ADDR=$1
OUTFILE=/tmp/$0.out
WORKFILE=$OUTFILE.work
SUDO=sudo

while true; do
    $SUDO nmap -sP -oX $WORKFILE $ADDR > /dev/null 2>&1
    $SUDO mv -f $WORKFILE $OUTFILE
    date +'%Y-%m-%d %H:%M:%S'
done
