#!/bin/bash
set -e
outdir="$1"

for json in ${outdir}/vadinfo.????.*.json
do
    sudo chown `whoami` ${json} || true
    if [ ! -r $json ]; then
        echo vadinfo json not found: $json
        continue
        #exit 4
    fi
    echo vadinfo: $json
    count=$(basename $json | cut -d. -f2)
    pid=$(basename $json | cut -d. -f3)
    memdump="${outdir}/memdump.${count}.${pid}.raw"
    sudo chown `whoami` $memdump || true
    if [ ! -r $memdump ]; then
        echo memdump not found: $memdump
        continue
        #exit 3
    fi
    echo memdump: $memdump
    mkdir -p "${outdir}/${count}"
    rm -f "${outdir}/${count}"/* || true
    ~/bin/volatility \
        -f $memdump \
        --profile=Win7SP0x64 \
        vaddump \
        -D "${outdir}/${count}" \
        -p ${pid} \
        >/dev/null
    echo done vaddump for $json
    ldr_json="${outdir}/ldrmodules.${count}.${pid}.json"
    rm -f $ldr_json || true
    ~/bin/volatility \
        -f $memdump \
        --profile=Win7SP0x64 \
        ldrmodules \
        --output=json \
        --output-file=${ldr_json} \
        -p ${pid} \
        >/dev/null
    echo done ldrmodules for $json

    section=0
    while read base size
    do
        if [ x"$base" == x -o ! $base -gt 0 ]; then
            echo bad base=:$base: skipping
            continue
        fi
        if [ x"$size" == x -o ! $size -gt 0 ]; then
            echo bad size=:$size: skipping
            continue
        fi
        sec_fmt=$(printf "%04d" ${section})
        imp_json="${outdir}/impscan.section${sec_fmt}.${count}.${pid}.json"
        if [ ! -f $imp_json ]; then
            echo running impscan for base=$base size=$size
            timeout 3m \
            ~/bin/volatility \
                -f $memdump \
                --profile=Win7SP0x64 \
                impscan \
                --base $base \
                --size $size \
                --output=json \
                --output-file=${imp_json} \
                --pid ${pid} \
                >/dev/null
            echo done impscan for base=$base size=$size
        else
            echo skipping impscan for base=$base size=$size
        fi
        section=$(expr $section + 1)
    done < <(
        jq '.impscan[] | .base, .size' $json \
            | xargs -n2
        )
done
