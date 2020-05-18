#!/bin/bash
set -e
indir_pfx="$1"
outdir_pfx="$2"
myhash="$3"
slot=$(printf "%02d" $4)

sample_fn="${indir_pfx}/${myhash}"
[ -f "${sample_fn}" ]
domain="win7-egg${slot}"
outdir="${outdir_pfx}/${myhash}"
mkdir -p ${outdir}

/home/linuxbrew/.linuxbrew/bin/python3 \
/home/wmartin45/src/vmi-unpack/scripts/pipeline_worker.py \
-f "${sample_fn}" \
-d ${domain} \
-s base \
-o "${outdir}"
