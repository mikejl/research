#!/bin/bash

TARGET=$1

cd /home/mike/research/raw

if [ ! -d "$TARGET" ]; then
  mkdir $TARGET 
fi

cd $TARGET

#ssh root@$TARGET "semanage fcontext -ln" > fcontext.org
semanage fcontext -ln > fcontext.org
cat fcontext.org | grep -v "=" > fcontext.txt



# **** END OF CODE ****
