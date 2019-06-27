#!/bin/bash

# add -x at end of line#1 to output command before it actually runs-- useful for debugging

# this assumes adaptor is plugged in & modules have been loaded
echo "This assumes adaptor is plugged in & modules have been loaded"

iwconfig

sudo systemctl stop NetworkManager.service
sudo airmon-ng check-kill
sudo ip link set wlxd46e0e1b95de down
sudo iwconfig wlxd46e0e1b95de mode monitor
sudo ip link set wlxd46e0e1b95de up

iwconfig

echo "\"sudo wireshark\" to run wireshark"
echo "\"sudo service network-manager restart\" to restart network manager and get out of monitor mode"
