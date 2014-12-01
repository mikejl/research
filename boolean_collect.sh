#!/bin/bash

#Pass in IPaddr
TARGET=$1


#Working Dir
cd /home/mike/research/raw/
mkdir $TARGET && cd $TARGET

ssh root@$TARGET "semanage boolean -ln" > boolean.txt && ssh root@$TARGET "semanage fcontext -ln" > fcontext.txt 

#List of bools for host
cat boolean.txt | awk {'print $1'} > bools.list

for p in $(cat bools.list)
 do
    ssh root@$TARGET "sesearch -b $p -AC" > $p.info
    PD=`cat $p.info | head -2 | tail -1 | awk {'print $3'}`
    echo $PD > $p.domain
    echo $p","$PD >> boolean.dlist
 done

