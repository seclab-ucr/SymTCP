#!/bin/bash

# Copyright (c) 2017, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

#
# Usage: ./run.sh UID GID
#

if [ $# -lt 2 ]; then
    echo "Usage: $0 uid gid"
    exit 1
fi

MUID="$1"
shift

MGID="$1"
shift

# Project name doesn't have the extension
PROJECT="tcp"

IMAGE="debian-9.2.1-x86_64"

# Verify that the specified group and user ids don't exist locally.
# If so, delete them. This may happen if the host OS is not Debian-based,
# where user ids may conflict with those preinstalled in the docker image.
GROUP=$(getent group $MGID | cut -d ':' -f 1)
USER=$(getent passwd $MUID | cut -d ':' -f 1)

if [ "x$USER" != "x" ]; then
  userdel $USER
fi

if [ "x$GROUP" != "x" ]; then
  groupdel $GROUP
fi

groupadd -g $MGID s2e
useradd -u $MUID -g s2e s2e

# S2E shared libraries are installed in a non-standard location,
# make sure the system can find them.
echo /opt/s2e/lib > /etc/ld.so.conf.d/s2e.conf
ldconfig

# prepare qemu-bridge helper
chmod u+s /opt/s2e/libexec/qemu-bridge-helper
# create bridge.conf
mkdir -p /opt/s2e/etc/qemu
echo "allow docker0" > /opt/s2e/etc/qemu/bridge.conf

ROOT="$(pwd)/s2e-docker"

# Run the rest of the script with the uid/gid provided, otherwise
# new files will be owned by root.
exec sudo -u s2e /bin/bash - << EOF

if [ ! -d "$ROOT" ]; then
  s2e init -b /opt/s2e "$ROOT"
fi

cd "$ROOT"

if [ ! -d "scripts" ]; then
  echo "Copying my scripts"

  cp /sym-tcp/scripts . -r
fi

if [ ! -d "images/$IMAGE" ]; then
  echo "Downloading image to images/$IMAGE"

  s2e image_build -d "$IMAGE"
fi 

if [ ! -d "projects/$PROJECT" ]; then
  echo "Creating new project in projects/$PROJECT"

  s2e new_project -n "$PROJECT" -i "$IMAGE" --no-target --type linux

  # modify s2e-configu.lua
  cat /sym-tcp/s2e-config.lua.mine >> "projects/$PROJECT/s2e-config.lua"
  sed -i '/\s*kleeArgs = {/a       "--use-query-log=solver:kquery",\n      "--use-end-query-pc-log",\n      "--flush-tbs-on-state-switch=false",\n      "--state-shared-memory=true",\n' "projects/$PROJECT/s2e-config.lua"

  # copy nc to the project folder
  cp /sym-tcp/bin/nc "projects/$PROJECT/"

  # add command to bootstrap.sh
  sed -i '/##### Please fetch and execute the target files manually   #####/a sudo ip addr add 172.17.0.2/16 dev enp0s3\nsudo ip link set enp0s3 up\n\n\$S2EGET nc && chmod +x nc\n\n./nc -vv -l -p 5555\n' "projects/$PROJECT/bootstrap.sh"

  # update launch-s2e.sh
  sed -i 's/-net none -net nic,model=e1000/-net nic -net bridge,br=docker0 -vnc 0.0.0.0:0,to=99,id=default/' "projects/$PROJECT/launch-s2e.sh"
  sed -i 's/export S2E_MAX_PROCESSES=1/export S2E_MAX_PROCESSES=48/' "projects/$PROJECT/launch-s2e.sh"

fi

#. s2e_activate

echo Running $PROJECT

cd projects/$PROJECT

./launch-s2e.sh

EOF
