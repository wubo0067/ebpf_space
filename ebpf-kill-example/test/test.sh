#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT")

# stop on error
set -e

# request sudo in advance
[ "$UID" -eq 0 ] || exec sudo bash "$0" "$@"

echo "-- Loading eBPF program."
sudo ./src/ebpf-kill-example > /tmp/ebpf-kill.log &

sleep 5

echo "-- Starting test process to kill."
$SCRIPT_PATH/loop.sh &
echo "-- PID of test process is $!."

disown
kill -9 $!

echo "-- Killed. Waiting for eBPF program to terminate .."
sleep 30

if (grep "$!" /tmp/ebpf-kill.log > /dev/null)
then
  printf "${GREEN}[ OK ]${NC} -- eBPF program ran as expected.\n"
  exit 0
else
  printf "${RED}[ FAIL ]${NC} -- eBPF program did not run as expected.\n"
  exit 1
fi
