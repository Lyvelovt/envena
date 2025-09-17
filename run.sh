#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: must be run as root."
  echo "Try 'sudo $0"
  exit 1
fi

python3 envena.py