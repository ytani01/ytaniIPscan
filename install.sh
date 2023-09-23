#!/bin/sh

PKGS="python3 python3-pip python3-venv nmap"

sudo apt install -y $PKGS

python3 -m venv env

. ./env/bin/activate

pip3 install -U pip

pip3 install -r requirements.txt
