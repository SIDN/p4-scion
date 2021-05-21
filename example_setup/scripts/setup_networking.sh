#!/bin/sh
ip link set dev enp0s8 up
ip link set dev enp0s9 up
ip link set dev enp0s10 up
ip link set dev enp0s16 up
ip a add 10.0.50.5/24 dev enp0s16

