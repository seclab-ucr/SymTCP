#!/bin/bash

docker run --privileged --net=host --rm -ti -w $(pwd) -v $HOME:$HOME gkso/sym-tcp /bin/bash

