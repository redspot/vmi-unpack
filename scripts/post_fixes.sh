#!/bin/bash
dbg=$1
tmpbase=$(basename $dbg | cut -c 1-11)
myhash=$(grep -l $tmpbase /home/wmartin45/borg-out/pipeline/1/*/stderr | cut -c 37-100)
/home/linuxbrew/.linuxbrew/bin/python3 \
    ~/src/vmi-unpack/scripts/pipeline_post.py \
    -w $dbg \
    -o /home/wmartin45/borg-out/pipeline/$myhash
