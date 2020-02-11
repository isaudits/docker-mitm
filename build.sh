#!/bin/bash

#docker pull debian:stable
#docker build --no-cache -t isaudits/mitm .
docker build -t isaudits/mitm .
docker image prune -f