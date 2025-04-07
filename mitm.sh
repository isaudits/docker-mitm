#!/bin/bash

dt=$(date "+%Y%m%d-%H%M%S")
logdir=`pwd`/data/$dt
mkdir $logdir

if [[ $(uname -s) == Linux ]]
then
    docker run -it --rm --net=host \
    -v $logdir:/usr/share/responder/logs \
    isaudits/mitm "$@"
else
    #NOTE - we should also map 137-138:137-138/udp but OSX has netbiosd running on those ports...
    
    docker run -it --rm \
    -v $logdir:/usr/share/responder/logs \
    -p 21:21 -p 25:25 -p 80:80 -p 88:88 -p 110:110 -p 135:135 -p 143:143 -p 389:389 -p 443:443 -p 445:445 -p 587:587 -p 3141:3141 -p 4443:4443 -p 8443:8443 \
    -p 88:88/udp -p 1434:1434/udp \
    isaudits/mitm "$@"
fi
