#!/bin/sh
#run in root

mv /bin/login /bin/login.secret
mv ./login /bin/
chown root /bin/login
