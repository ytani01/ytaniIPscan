#!/bin/sh -e
#
# Copyright (c) 2023 Yoichi Tanibayashi
#

VENV_DIR=$1
echo "VENV_DIR=$VENV_DIR"

shift

CMD_LINE=$*
echo "CMD_LINE=$CMD_LINE"

echo

. $VENV_DIR/bin/activate

exec $CMD_LINE
