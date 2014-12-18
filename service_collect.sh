#!/bin/bash

# look at ps Z -C <service name> or ps Z -p <pid>

TARGET=$1

cd /home/mike


if [ ! -d "$TARGET" ]; then
  mkdir $TARGET 
fi

cd $TARGET


#ssh root@$TARGET "systemctl --type=service --no-legend" > service.txt
systemctl --type=service --no-legend > service.txt

# Chkconfig not needed with systemd may need it for SysVinit
#ssh root@$TARGET "chkconfig --list" > chkconfig.txt

#ssh root@$TARGET "ps -efZ" > psZ.txt
ps -efZ > psZ.txt

# this cuts off some of the information.  Use psZ and service.txt
#ssh root@$TARGET "ps axo pid,fname,context" > psaxo.txt

cat service.txt | awk {'print $1'} > service.names
cat service.txt | grep "running" | awk {'print $1'} > service.running
cut -d. -f1 service.running > service.psnames 

for s in $(cat service.psnames)
 do
    #ssh root@$TARGET "ps -ejHZ | grep $s" > $s.info
    ps -ejHZ | grep $s > $s.info
    #ssh root@$TARGET "ps Z -C $s" > $s.info2
    ps Z -C $s > $s.info2
 done




# **** END OF CODE ****
