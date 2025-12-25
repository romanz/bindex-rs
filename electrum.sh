#!/bin/bash
set -eux

export ZMQ_ADDR=tcp://127.0.0.1:55555
./run.sh -c `mktemp` -e $*
