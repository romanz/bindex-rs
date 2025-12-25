#!/bin/bash
set -eux

export ZMQ_ADDR=tcp://127.0.0.1:55555
./bindex.sh -c `mktemp` -e $*
