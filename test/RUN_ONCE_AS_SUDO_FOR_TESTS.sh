#!/bin/bash
if [[ $EUID > 0 ]]
  then echo "This script must be run with sudo."
  exit
fi

mkdir -p /run/user/$(id -u $SUDO_USER)
chown $SUDO_USER /run/user/$(id -u $SUDO_USER)
