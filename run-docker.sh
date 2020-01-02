#!/bin/bash

docker run --privileged --net=host --rm -ti -w $(pwd) -v $HOME:$HOME gkso/sym-tcp /sym-tcp/run.sh $(id -u) $(id -g)

