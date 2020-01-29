import re
import sys

import click
from intervaltree import Interval, IntervalTree

exec_patt_raw = r'Tracing instruction at (?P<addr>[^,]+),'
write_patt_raw = r'Memory is being WRITTEN at (?P<addr>[^,]+),'
possible_api_raw = r'^[a-zA-Z]+:'
exec_re = re.compile(exec_patt_raw)
write_re = re.compile(write_patt_raw)
possible_api_re = re.compile(possible_api_raw)

IMAGE_BASE = 0x400000

class Section:
    def __init__(self, vaddr=0, vsize=0):
        self.virtual_address = vaddr
        self.virtual_size = vsize
    def __lt__(self, rhs):
        return self.virtual_address < rhs.virtual_address
    def __repr__(self):
        return ("Section("
                f"virtual_address=0x{self.virtual_address:x}, "
                f"virtual_size=0x{self.virtual_size:x}"
                ")")


class AddrTrack(dict):
    def __init__(self, name):
        self.last = None
        self.name = name


def make_mock_binary(_section_pts):
    class Bin(object):
        pass
    pos = 0
    _bin = Bin()
    _bin.sections = []
    while pos < len(_section_pts):
        virtual_address = int(_section_pts[pos], 16)
        virtual_size = int(_section_pts[pos+1], 16)
        _section = Section(virtual_address, virtual_size)
        _bin.sections.append(_section)
        pos += 2
    get_vaddr = lambda s: s.virtual_address
    _bin.sections = sorted(_bin.sections)
    return _bin


def align(vaddr, page_size=4096):
    """page align an address"""
    slack = vaddr % page_size
    pad = page_size - slack
    aligned_vaddr = vaddr + pad
    return aligned_vaddr


def slice_sections(_binary):
    _tree = IntervalTree()
    _tree[0:_binary.sections[0].virtual_address] = 'header'
    nsecs = len(_binary.sections)
    for i in range(nsecs - 1):
        start = _binary.sections[i].virtual_address
        end = start + _binary.sections[i].virtual_size
        _tree[start:end] = name = f"section{i}:0x{start:x}"
        padded_end = _binary.sections[i+1].virtual_address
        print(f"loop start=0x{start:x} end=0x{end:x} padded_end=0x{padded_end:x} name={name}")
        if end < padded_end:
            _tree[end:padded_end] = name = f"pad{i}:0x{end:x}"
            print(f"loop start=0x{start:x} end=0x{end:x} padded_end=0x{padded_end:x} name={name}")
    start = _binary.sections[-1].virtual_address
    end = start + _binary.sections[-1].virtual_size
    _tree[start:end] = name = f"section{nsecs - 1}:0x{start:x}"
    padded_end = align(end)
    print(f"last start=0x{start:x} end=0x{end:x} padded_end=0x{padded_end:x} name={name}")
    if end < padded_end:
        _tree[end:padded_end] = name = f"pad{nsecs - 1}:0x{end:x}"
        print(f"last start=0x{start:x} end=0x{end:x} padded_end=0x{padded_end:x} name={name}")
    return _tree


@click.command()
@click.argument('log_fn', type=click.File('r'))
@click.argument('section_points', nargs=-1)
def main(log_fn, section_points):
    if len(section_points) < 2:
        raise click.BadParameter('at least one section is needed') 
    if len(section_points) % 2 != 0:
        raise click.BadParameter('the section points must be even, '
                'one start and one size for each section') 
    binary = make_mock_binary(section_points)
    #print(binary.sections)
    section_tree = slice_sections(binary)
    #for iv in section_tree:
    #    print(f"begin=0x{iv.begin:x} end=0x{iv.end:x} data={iv.data}")
    #print(section_tree)
    track_exec = AddrTrack("EXEC")
    track_write = AddrTrack("WRITE")
    i = 0
    for line in log_fn:
        i += 1
        #if i >= 100:
        #    break
        #print(f"{i}:[{line.strip()}]")
        addr = None
        exec_m = exec_re.search(line)
        if exec_m:
            addr = int(exec_m.group('addr'), 16)
            track = track_exec
        else:
            write_m = write_re.search(line)
            if write_m:
                addr = int(write_m.group('addr'), 16)
                track = track_write
            else:
                api_m = possible_api_re.search(line)
                if api_m:
                    print(f"{i}:[{line.strip()}]")
        if addr is None:
            continue
        if not (addr & IMAGE_BASE):
            #print(f"addr {addr:x} outside of image base")
            continue
        #strip imagebase
        addr &= 0xffff
        iv_set = section_tree[addr]
        if not iv_set:
            print(f"addr 0x{addr:x} not found in section_tree")
            continue
        for iv in iv_set:
            #print(f"addr 0x{addr:x} found in section {iv.data}")
            if iv.data != track.last:
                #print(f"{i}:[{line.strip()}]")
                if iv.data.startswith('header'):
                    pass
                    #print(f"{track.name} addr 0x{addr:x} found in section {iv.data}")
                else:
                    print(f"{track.name} to {iv.data}")
                if (track.last is not None
                        and track.name == "EXEC"
                        and not iv.data.startswith('pad')
                        and not (iv.data.startswith('header') or track.last.startswith('header'))
                   ):
                    print(f"Section hop detected: last:{track.last} -> current:{iv.data}")
            if (track.name == "EXEC"
                    and iv.data in track_write
                    and not track_write[iv.data]
                    and not iv.data.startswith('pad')
               ):
                #print(f"{i}:[{line.strip()}]")
                print(f"write+exec detected: addr:0x{addr:x} -> current:{iv.data}")
                track_write[iv.data] = True
            if not iv.data.startswith('header'):
                track.last = iv.data
            if iv.data not in track:
                track[iv.data] = False

if __name__ == '__main__':
    main()
