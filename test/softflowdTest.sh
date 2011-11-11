#!/bin/bash
#Generate flows from the local computer
sudo softflowd -i wlan0 -n 127.0.0.1:8991 -v 9 -d -D
