#!/home/linuxbrew/.linuxbrew/bin/python3
from __future__ import print_function

import click
from glob import glob
import json
import os
import os.path
import re

dump_dir_patt = r'^[0-9]{4}$'
dump_dir_re = re.compile(dump_dir_patt)


def find_vadinfo_files(sh_glob='vadinfo.????.*.json'):
    return glob(sh_glob)


def find_dump_dirs(_path):
    _dirs = []
    with os.scandir(_path) as _iter:
        for entry in _iter:
            if entry.is_dir() and dump_dir_re.match(entry.name):
                _dirs.append(entry.name)
    return _dirs


def parse_vadinfo(fn):
    with open(fn, 'r') as fd:
        res = json.load(fd)
        vads = [dict(zip(res['columns'], r)) for r in res['rows']]
    return (vads, res)


def find_orig_exe(stem, vads, glob_tmpl='{}.????????.0x{:016x}-0x{:016x}.dmp'):
    exe_fn = None
    fn_re = re.compile(r'\\' + stem + r'[^\\]*.exe')
    for vad in vads:
        if fn_re.search(vad['FileNameWithDevice']):
            fn = (f'{stem}.exe')[:14]
            exe_fn = glob_tmpl.format(fn, vad['Start'], vad['End'])
            break
    return exe_fn


@click.command()
@click.argument('dump_path')
def main(dump_path):
    orig_pwd = os.getcwd()
    os.chdir(dump_path)
    vadinfo_fns = find_vadinfo_files()
    assert len(vadinfo_fns) > 0
    my_vads = {}
    for vinfo in vadinfo_fns:
        key = vinfo.split('.')[1]
        my_vads[key] = lambda: None  # make a simple object
        my_vads[key].vads, _ = parse_vadinfo(vinfo)
    for path in find_dump_dirs(dump_path):
        if path not in my_vads:
            continue
        any_dmp = os.path.join(dump_path, path, '*.dmp')
        dmps = glob(any_dmp)
        if dmps and len(dmps):
            dmp_fn = os.path.basename(dmps[0])
            exe_stem, _ = dmp_fn.split('.', 1)
            exe_glob = find_orig_exe(exe_stem, my_vads[path].vads)
            if exe_glob is not None:
                full_glob = os.path.join(dump_path, path, exe_glob)
                found = glob(full_glob)
                if found and len(found) == 1:
                    print(found[0])
    os.chdir(orig_pwd)


if __name__ == '__main__':
    main()
