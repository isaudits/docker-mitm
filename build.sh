#!/bin/bash

#docker build --no-cache -t isaudits/mitm .
docker build -t isaudits/mitm .
docker image prune -f