#!/bin/sh
SCION_PATH=~/scion/bin
$SCION_PATH/scion ping --sciond 127.0.0.27:30255 1-ff00:0:111,10.0.10.10 -c 1
$SCION_PATH/scion ping --sciond 127.0.0.27:30255 1-ff00:0:110,10.0.30.10 -c 1
$SCION_PATH/scion ping --sciond 127.0.0.19:30255 1-ff00:0:110,10.0.30.10 -c 1
$SCION_PATH/scion ping --sciond 127.0.0.19:30255 1-ff00:0:112,10.0.20.10 -c 1
$SCION_PATH/scion ping --sciond 127.0.0.12:30255 1-ff00:0:111,10.0.10.10 -c 1
$SCION_PATH/scion ping --sciond 127.0.0.12:30255 1-ff00:0:112,10.0.20.10 -c 1

