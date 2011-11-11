#!/bin/bash 
d=0
while :
    do 
        `/usr/bin/nslookup www.google.com.tr > /dev/null`
        sleep 0.2
        `/usr/bin/dig yahoo.com A +noall +answer > /dev/null`
        sleep 0.2
        (( d++ ))
        if [ $d -eq 10 ]
        then
            d=0
            echo "Now sleep for 2 secs"
            sleep 2
        fi
    done
