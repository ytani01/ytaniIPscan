#!/bin/sh -e
#
# Copyright (c) 2023 Yoichi Tanibayashi
#

VENV_DIR=$1
if [ -n $VENV_DIR -a -d $VENV_DIR ]; then
    echo "VENV_DIR=$VENV_DIR"
else
    echo "ERROR: VENV_DIR=$VENV_DIR"
    exit
fi

shift

CMD_LINE=$*
echo "CMD_LINE=$CMD_LINE"

echo

. $VENV_DIR/bin/activate

exec $CMD_LINE
