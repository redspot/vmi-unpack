import json
import logging
import ntpath
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import namedtuple
from contextlib import ExitStack, contextmanager  # noqa
from datetime import datetime
from glob import glob
from multiprocessing import Manager, Process
from multiprocessing.managers import BaseManager
from pathlib import Path
from random import randrange
# from tempfile import TemporaryDirectory
from threading import Thread
from traceback import format_exception_only

import click

import libvirt

from requests.exceptions import RequestException

from vmcloak.agent import Agent

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
        format='%(asctime)s %(levelname)s:%(name)s %(message)s',
        )

LIBVIRT_CONN_SINGLETON = None
CODE_HOME = Path('/home/wmartin45/src/vmi-unpack')
SCRIPT_PREFIX = CODE_HOME / 'scripts'
MASTER_REDIRECTS = CODE_HOME / 'data/win7_master_dll_redirects.json'

RC_SUCCESS = 0
RC_NO_VADS = 1 << 0
RC_VM_EXIT = 1 << 1
RC_SAMPLE_TIMEOUT = 1 << 2
RC_REVERT_TIMEOUT = 1 << 3
RC_REVERT_FAILED = 1 << 4
RC_NX_DOMAIN = 1 << 5
RC_VM_START_FAILED = 1 << 6
RC_NO_AGENT_IP = 1 << 7
RC_FIFO_TIMEOUT = 1 << 8
RC_UNCAUGHT_EXC = 1 << 9


class Subprocess():
    """Context manager to run a process.

    :param int exit_wait:
        How long (seconds) to wait after sending SIGTERM to send SIGKILL.
        (Default: 5)

    This runs a process when it is entered, and kills the process when exited.

    The positional arguments to this constructor are the arguments to the
    subprocess.  The keyword arguments (other than the two mentioned above) are
    passed through to :class:`subprocess.Popen`.

    """
    def __init__(
        self, *args, exit_wait=5, **kwargs
    ):
        self.exit_wait = exit_wait

        self.args = list(map(str, args))
        self.kwargs = kwargs

        self.arg_str = ' '.join(self.args)

        self.proc = None

    def __enter__(self):
        logger.debug(f"Subprocess: starting"
                     f" args=[{self.arg_str}]")
        self.proc = subprocess.Popen(self.args, **self.kwargs)
        time.sleep(3)
        try:
            self.poll()
            logger.debug(f"Subprocess: pid={self.proc.pid}"
                         f" args=[{self.arg_str}]")
        except subprocess.SubprocessError:
            logger.debug(f"Subprocess: pid={self.proc.pid}"
                         f" args=[{self.arg_str}]"
                         f" returncode={self.proc.returncode}")
            raise subprocess.SubprocessError('early termination')
        return self

    def __exit__(self, *exc_info):
        try:
            self.poll()
            logger.debug(f"Subprocess: pid={self.proc.pid}"
                         " still running. terminating now.")
            self.proc.terminate()
            try:
                self.proc.wait(self.exit_wait)
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " terminated.")
            except subprocess.TimeoutExpired:
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " did not terminate. killing.")
                self.proc.kill()
                self.proc.wait()
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " killed.")
        except PermissionError:
            try:
                subprocess.run((f'sudo kill {self.proc.pid}').split())
                self.proc.wait(self.exit_wait)
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " terminated.")
            except subprocess.TimeoutExpired:
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " did not terminate. killing.")
                subprocess.run((f'sudo kill -9 {self.proc.pid}').split())
                self.proc.wait()
                logger.debug(f"Subprocess: pid={self.proc.pid}"
                             " killed.")
        except subprocess.SubprocessError:
            logger.debug(f"Subprocess: pid={self.proc.pid}"
                         f" returncode={self.proc.returncode}")

    def poll(self):
        """throws exception if process not running"""
        rcode = self.proc.poll()
        if rcode is not None:
            raise subprocess.SubprocessError


class CapturePackets(Subprocess):
    """Context manager to run ``tcpdump``.

    :param pcap_filename: The file to save captured packets in.
    :param interface: The interface to capture packets on.

    You may supply additional arguments to ``tcpdump``, such as a capture
    filter, as extra positional arguments.  You may supply keyword arguments
    that will be passed to :class:`analysis_utils.subproc.Subprocess`.

    """
    def __init__(self, pcap_filename, interface, *args, **kwargs):
        self.pcap_filename = pcap_filename

        tcpdump_args = [
            '/usr/sbin/tcpdump',
            '-B',
            '16384',
            '-i',
            interface,
            '-U',
            '-w',
            pcap_filename,
            '-s',
            '0',
        ]

        tcpdump_args.extend(args)

        super(CapturePackets, self).__init__(*tcpdump_args, **kwargs)


class RunUnpack(Subprocess):
    """
    sudo ~/src/vmi-unpack/bin/unpack
    -d win7-borg
    -r ~/win7-borg-rekall.json
    -o ~/borg-out/
    -n sample_895d.exe
    -v Win7SP1x64
    -fl
    2> ~/win7-borg-unpack.log
    """
    def __init__(self, domain, process_name, outdir, *args,
                 launcher_bin='~/src/vmi-unpack/scripts/launch_unpack.sh',
                 unpack_bin='~/src/vmi-unpack/bin/unpack',
                 rekall_fn='~/win7-borg-rekall.json',
                 logfile=None,
                 vol_profile='Win7SP1x64',
                 follow_children=True,
                 imagebase_only=False,
                 dryrun=False,
                 **kwargs):
        self.domain = domain
        self.process_name = process_name
        self.outdir = outdir
        self.launcher_bin = Path(launcher_bin).expanduser()
        self.unpack_bin = Path(unpack_bin).expanduser()
        self.rekall_fn = Path(rekall_fn).expanduser()
        self.vol_profile = vol_profile

        if dryrun:
            unpack_args = [
                    'sleep',
                    str(10 + randrange(50)),
                    ]
        else:
            unpack_args = [
                    self.launcher_bin,
                    self.unpack_bin,
                    '-d', self.domain,
                    '-n', self.process_name,
                    '-o', self.outdir,
                    '-r', self.rekall_fn,
                    '-v', self.vol_profile,
                    '-c', '/home/wmartin45/src/vmi-unpack/unpack.cfg',
                    ]

            if follow_children:
                unpack_args.append('-f')
            if not imagebase_only:
                unpack_args.append('-l')

            unpack_args.extend(args)

        super(RunUnpack, self).__init__(
                *unpack_args,
                stdout=None, stderr=logfile,
                preexec_fn=os.setpgrp,  # force sudo to forward signals
                **kwargs)


class AgentManager(BaseManager):
    pass


class LibvirtVM():
    def __init__(self, vm_name):
        self.dom = None
        self.exc = None
        self.vm_name = vm_name

    def __enter__(self):
        connect_to_libvirt()
        try:
            self.dom = get_domain(self.vm_name)
            self.start()
        except libvirt.libvirtError as exc:
            self.exc = exc
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.kill()

    def start(self):
        start_domain(self.dom)
        time.sleep(1)
        if not self.is_running():
            raise libvirt.libvirtError(
                    f"error: cannot start domain {self.vm_name}")

    def kill(self):
        kill_domain(self.dom)

    def is_running(self):
        if self.exc is not None or self.dom is None:
            return False
        state, _ = self.dom.state()
        return state == libvirt.VIR_DOMAIN_RUNNING

    def get_error(self):
        rc = None
        mesg = None
        if self.dom is None:
            rc = RC_NX_DOMAIN
            mesg = format_exception_only(type(self.exc), self.exc)
        elif self.exc is not None:
            rc = RC_VM_START_FAILED
            mesg = format_exception_only(type(self.exc), self.exc)
        return (rc, mesg)


def connect_to_libvirt():
    global LIBVIRT_CONN_SINGLETON
    if not isinstance(LIBVIRT_CONN_SINGLETON, libvirt.virConnect):
        LIBVIRT_CONN_SINGLETON = libvirt.open(None)
        logger.debug("connected to libvirt")
    return LIBVIRT_CONN_SINGLETON


def get_domain(_dom_name):
    global LIBVIRT_CONN_SINGLETON
    return LIBVIRT_CONN_SINGLETON.lookupByName(_dom_name)


def libxl_is_domain_active(_dom):
    cmd = ["sudo", "xl", "list", _dom.name()]
    proc = subprocess.run(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.DEVNULL,
            )
    return not proc.returncode


def libxl_kill_domain(_dom):
    cmd = ["sudo", "xl", "destroy", _dom.name()]
    proc = subprocess.run(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.DEVNULL,
            )
    return not proc.returncode


def kill_domain(_dom):
    try:
        _dom.destroy()
        logger.debug(f"destroyed domain {_dom.name()}")
        return True
    except libvirt.libvirtError:
        pass
    if libxl_is_domain_active(_dom):
        return libxl_kill_domain(_dom)
    return False


def __start_domain(_dom):
    _dom.create()
    logger.debug(f"started domain {_dom.name()}")


def start_domain(_dom):
    try:
        if not _dom.isActive():
            __start_domain(_dom)
    except libvirt.libvirtError:
        kill_domain(_dom)
        time.sleep(1)
        __start_domain(_dom)


def dumpxml(_dom):
    return ET.fromstring(_dom.XMLDesc())


def _get_mac_addrs(_xml):
    mac_addr = None
    egress_mac_addr = None

    # full valid xpath to mac addr, but python ET doesnt support full xpath
    '''
    string(//interface[@type='network'
           and source/@network='hostonly']/mac/@address)
    '''
    iface_xpath = ".//interface[@type='network']"
    agent_network = 'hostonly'
    egress_network = 'default'
    ifname_xpath = "./source[@network='{}']"

    for node in _xml.findall(iface_xpath):
        if mac_addr is None:
            if node.find(ifname_xpath.format(agent_network)) is not None:
                mac_addr = node.find("mac").attrib['address']
        if egress_mac_addr is None:
            if node.find(ifname_xpath.format(egress_network)) is not None:
                egress_mac_addr = node.find("mac").attrib['address']
    logger.debug(f" mac_addr={mac_addr}"
                 f" egress_mac_addr={egress_mac_addr}")
    return (mac_addr, egress_mac_addr)


def __get_network_info(_dom, _xml):
    guest_ip = None
    egress_nic = None
    mac_addr, egress_mac_addr = _get_mac_addrs(_xml)
    ifaces = _dom.interfaceAddresses(
            libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
    for key, val in ifaces.items():
        if val['addrs'] and val['hwaddr'] == mac_addr:
            guest_ip = val['addrs'][0]['addr']
        if val['addrs'] and val['hwaddr'] == egress_mac_addr:
            egress_nic = key
    logger.debug(f"domain={_dom.name()}"
                 f" guest_ip={guest_ip}"
                 f" egress_nic={egress_nic}")
    return (guest_ip, egress_nic)


def get_network_info(_dom, _xml, tries=24, sleep=5):
    guest_ip = None
    egress_nic = None
    for _ in range(tries):
        guest_ip, egress_nic = __get_network_info(_dom, _xml)
        if guest_ip is not None:
            break
        time.sleep(sleep)
    return (guest_ip, egress_nic)


def get_disk_fn(_xml):
    qcow_fn = None
    disk_xpath = ".//disk[@device='disk']/source"
    disk = _xml.find(disk_xpath)
    if disk is not None:
        qcow_fn = disk.get('file')
    logger.debug(f"qcow_fn={qcow_fn}")
    return qcow_fn


def revert_snapshot(_qcow_fn, _snapname, timeout=30):
    cmd = ["qemu-img", "snapshot", "-a", _snapname, _qcow_fn]
    try:
        proc = subprocess.run(cmd, timeout=timeout, capture_output=True)
        logger.debug(f"revert_snapshot: cmd={cmd}")
        return proc.returncode
    except subprocess.TimeoutExpired as exc:
        logger.error(f"timeout reverting snapshot:\n"
                     f"cmd={exc.cmd}\n"
                     f"output={exc.output}\n"
                     )
        return -1


def create_agent(_ip, _port=8000):
    if _ip is None:
        raise RuntimeError('agent ip cannot be None')
    return Agent(_ip, _port)


def ping_agent(_agent, timeout=0):
    if (timeout <= 0):
        _start_time = None

        def predicate():
            return True
    else:
        _start_time = time.time()
        _time_limit = _start_time + timeout

        def predicate():
            return time.time() < _time_limit
    while predicate():
        try:
            _agent.ping()
            break
        except Exception:
            pass
    if _start_time is not None:
        elapsed = time.time() - _start_time
        logger.debug(f"ping_agent took {elapsed} seconds")


def upload_sample(_agent, _fd, dest_path='c:/users/customer/music',
                  dest_fn='c1a73266.exe'):
    _upload_path = ntpath.join(
            ntpath.normpath(dest_path),
            ntpath.normpath(dest_fn),
            )
    _data = _fd.read()
    for _ in range(10):
        try:
            _agent.upload(_upload_path, _data)
            logger.debug(f"uploaded sample to {_upload_path}")
            return
        except RequestException:
            time.sleep(4)
            logger.warning(f"retrying sample upload to {_upload_path}")
    raise RuntimeError


def exec_sample(_agent, dest_path='c:/users/customer/music',
                dest_fn='c1a73266.exe',
                _async=True,
                _dict=None):
    _exec_path = ntpath.join(
            ntpath.normpath(dest_path),
            ntpath.normpath(dest_fn),
            )
    logger.debug(f"executing sample at {_exec_path}")
    _result = _agent.execute(_exec_path, _async=_async)
    logger.debug(f"executed sample at {_exec_path}")
    if _dict is not None:
        try:
            result_dict = json.loads(_result.content)
            _dict.update(result_dict)
        except Exception:
            try:
                _dict['content'] = str(_result.content)
            except Exception:
                pass


class WatchSampleExec:
    def __init__(self, _agent, *args, **kwargs):
        self.agent = _agent
        self.pkg = namedtuple(
                'ForkPackage',
                ['agent_manager',
                 'agent_proxy',
                 'dict_manager',
                 'dict',
                 'process'])
        self.args = args
        self.kwargs = kwargs

    def __enter__(self):
        AgentManager.register('AgentProxy', callable=lambda: self.agent)
        self.pkg.agent_manager = AgentManager()
        self.pkg.agent_manager.start()
        self.pkg.agent_proxy = self.pkg.agent_manager.AgentProxy()
        self.pkg.dict_manager = Manager()
        self.pkg.dict = self.pkg.dict_manager.dict()
        self.kwargs.update({'_dict': self.pkg.dict, '_async': False})
        self.pkg.process = Process(
                target=exec_sample,
                args=(self.pkg.agent_proxy,),
                kwargs=self.kwargs,
                )
        self.pkg.process.start()
        return self

    def __exit__(self, *exc_info):
        if self.pkg.process.is_alive():
            self.pkg.process.terminate()
            logger.info("watch_exec did not terminate")
            time.sleep(0.2)
            if self.pkg.process.is_alive():
                self.pkg.process.kill()
        if len(self.pkg.dict.keys()):
            logger.info(
                    f"watch_exec returned {self.pkg.dict}")
        else:
            logger.info("watch_exec did not return any output")


def fork_exec_sample(_agent, **kwargs):
    pkg = namedtuple('ForkPackage',
                     ['agent_manager',
                      'agent_proxy',
                      'dict_manager',
                      'dict',
                      'process'])
    AgentManager.register('AgentProxy', callable=lambda: _agent)
    pkg.agent_manager = AgentManager()
    pkg.agent_manager.start()
    pkg.agent_proxy = pkg.agent_manager.AgentProxy()
    pkg.dict_manager = Manager()
    pkg.dict = pkg.dict_manager.dict()
    kwargs.update({'_dict': pkg.dict, '_async': False})
    p = Process(target=exec_sample,
                args=(pkg.agent_proxy,),
                kwargs=kwargs,
                )
    p.start()
    pkg.process = p
    return pkg


def watch_unpack_and_vm(unpack, vm, timeout_slice=30, timeout_tries=30):
    rc = 0
    try:
        for i in range(timeout_tries):
            try:
                unpack.proc.wait(timeout=timeout_slice)
                logger.info("unpack exited before timeout")
                return rc
            except subprocess.TimeoutExpired:
                logger.debug("checking vm...")
                if not vm.is_running():
                    logger.error("vm is not running")
                    time_passed = (i + 1) * timeout_slice
                    raise subprocess.TimeoutExpired(
                            f'libvirt: {vm.vm_name}',
                            time_passed)
        if unpack.proc.poll() is None:
            time_passed = timeout_tries * timeout_slice
            raise subprocess.TimeoutExpired(
                    str(unpack.proc.args),
                    time_passed)
    except subprocess.TimeoutExpired as exc:
        if exc.cmd.startswith('libvirt'):
            mesg = "VM exited"
            rc = RC_VM_EXIT
        else:
            mesg = "sample did not exit"
            rc = RC_SAMPLE_TIMEOUT
        logger.warning(f"{mesg}"
                       f" after {exc.timeout} seconds")
    return rc


def get_slot_and_basename(_dump_file, _dump_dir):
    _dump_path = Path(_dump_file)
    _rel_path = _dump_path.relative_to(_dump_dir)
    _slot = str(_rel_path.parent)
    if len(_slot) != 4:
        logger.error("error: cannot find dump slot"
                     f"\n_dump_file={_dump_file}"
                     f"\n_dump_dir={_dump_dir}"
                     f"\n_rel_path={_rel_path}"
                     f"\n_slot={_slot}"
                     )
        return (None, None)
    _old_name = str(_rel_path.name)
    logger.debug("get_slot_and_basename:"
                 f" _dump_file={_dump_file}"
                 f" _dump_dir={_dump_dir}"
                 f" _rel_path={_rel_path}"
                 f" _slot={_slot}"
                 f" _old_name={_old_name}"
                 )
    return (int(_slot), _old_name)


def call_fix_binary(_dump_file, _dump_dir, _slot, _old_name, _outdir, *_args,
                    _script_name='fix_binary.py',
                    _redirects=MASTER_REDIRECTS,
                    **kwargs):
    '''
    fix_binary.py
        ~/borg-out/hello_mpress/hello_mpress.e.7dc58480.0x0000000000400000-0x0000000000408fff.dmp.0003
        hello_mpress_unpacked.exe
        ~/borg-out
        0002
        ../data/win7_master_dll_redirects.json
    '''
    _old_stem = _old_name.split('.', 1)[0]
    _new_name = f'{_old_stem}.{int(_slot):04}.unpacked.exe'
    _new_path = Path(_outdir) / _new_name
    args = list(map(str, [
        sys.executable,
        SCRIPT_PREFIX / _script_name,
        _dump_file,
        _new_path,
        _dump_dir,
        _slot,
        _redirects,
        ] + _args))
    try:
        logger.debug(f"starting {_script_name} args={args}")
        p = subprocess.run(args, capture_output=True, check=True, text=True,
                           **kwargs)
        logger.debug(f"completed {_script_name} returncode={p.returncode}")
        return True
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1337:
            logger.error(f"error: {_script_name} returned {exc.returncode}"
                         f"\nstdout:\n{exc.stdout}"
                         f"\nstderr:\n{exc.stderr}")
        else:
            logger.debug(f"completed {_script_name}"
                         f" returncode={exc.returncode}")
        return False
    finally:
        with open(f'{_new_path}.log', 'w') as out:
            out.write(p.stdout)
        with open(f'{_new_path}.err', 'w') as out:
            out.write(p.stderr)
        logger.debug(f"stdout:\n{p.stdout}")
        logger.debug(f"stderr:\n{p.stderr}")


def call_post_dump(_dir,
                   _script_name='post_dump.sh'):
    args = [
            SCRIPT_PREFIX / _script_name,
            _dir,
            ]
    try:
        logger.debug(f"starting {_script_name} args={args}")
        p = subprocess.run(args, capture_output=True, check=True, text=True)
        logger.debug(f"completed {_script_name} returncode={p.returncode}")
        logger.debug(f"stdout:\n{p.stdout}")
    except subprocess.CalledProcessError as exc:
        logger.error(f"Error: {_script_name} returned {exc.returncode}"
                     f"\nstdout:\n{exc.stdout}"
                     f"\nstderr:\n{exc.stderr}")
        # os.rename(_dir, f"{_dir}_debug")
        # os.mkdir(_dir)


def call_find_vad(_dir,
                  _script_name='find_vad.py'):
    '''
    ./find_vad.py ~/borg-out/
    '''
    args = [
            sys.executable,
            SCRIPT_PREFIX / _script_name,
            _dir,
            ]
    try:
        logger.debug(f"starting {_script_name} args={args}")
        p = subprocess.run(args, capture_output=True, check=True, text=True)
        logger.debug(f"completed {_script_name} returncode={p.returncode}")
        lines = p.stdout.split()
        return lines
    except subprocess.CalledProcessError as exc:
        logger.error(f"error: {_script_name} returned {exc.returncode}"
                     f"\nstderr:\n{exc.stderr}")
        return None


def chown_workdir(_workdir):
    subprocess.check_call(
        (f'sudo chown -R {os.getuid()}:{os.getgid()} {_workdir}').split()
    )


def fix_and_save_vads(_dump_files, _workdir, _outdir,
                      *args, **kwargs):
    any_fixes = False
    for _file in _dump_files:
        logger.debug(f'trying to fix {_file}')
        slot, basename = get_slot_and_basename(_file, _workdir)
        if slot is not None:
            any_fixes = call_fix_binary(_file, _workdir, slot,
                                        basename, _outdir,
                                        *args, **kwargs) \
                        or any_fixes
            out_name = f'{basename}.{int(slot):04}'
            out_path = Path(_outdir) / out_name
            shutil.copy(_file, str(out_path))
            logger.debug(f"copy {_file} to {out_path}")
            for _json in glob(str(Path(_workdir) / '*.json')):
                shutil.copy(_json, str(_outdir))
                logger.debug(f"copy {_json} to {_outdir}")
        else:
            logger.debug(f'slot was None. not fixing')
    return any_fixes


@contextmanager
def tempfifo(_workdir):
    fifo_path = Path(_workdir) / "fifo"
    try:
        os.mkfifo(fifo_path)
        yield fifo_path
    finally:
        os.unlink(fifo_path)


def open_fifo(fifo_fn):
    logger.debug(f"reading from fifo {fifo_fn}...")
    # blocks until both sides are open
    with open(fifo_fn, 'rb'):
        pass
    logger.debug(f"done reading from fifo {fifo_fn}...")


def wait_for_fifo(fifo_fn, dry_run=False):
    if not dry_run:
        fifo_barrier = Thread(
                target=open_fifo,
                args=(fifo_fn,))
        fifo_barrier.start()
        fifo_barrier.join(timeout=5)
        if fifo_barrier.is_alive():
            return False
    return True


def main(workdir, outdir, dry_run):
    rc = RC_SUCCESS
    outdir = Path(outdir).expanduser()
    exec_start_ts = datetime.now()
    if not dry_run:
        call_post_dump(workdir)
    exec_end_ts = datetime.now()
    exec_runtime = (exec_end_ts - exec_start_ts)
    chown_workdir(workdir)
    dumpfiles = call_find_vad(workdir)
    if dumpfiles is None:
        logger.error("no dumpfiles produced")
        dry_run or shutil.rmtree(workdir, ignore_errors=True)
        return (rc + RC_NO_VADS), exec_runtime
    args = ['--debug'] if dry_run else []
    if fix_and_save_vads(dumpfiles, workdir, outdir, *args):
        dry_run or shutil.rmtree(workdir, ignore_errors=True)
    else:
        logger.error("no EXEs created, but deleting workdir anyway")
        dry_run or shutil.rmtree(workdir, ignore_errors=True)
    return rc, exec_runtime


@click.command()
@click.option('-w', '--workdir', required=True,
              type=click.Path(exists=True))
@click.option('-o', '--outdir', required=True,
              type=click.Path(exists=True))
@click.option('--dry-run', is_flag=True)
def cli(workdir, outdir, dry_run):
    start_ts = datetime.now()
    logger.info(f"starting pipeline_worker:"
                f" workdir={workdir}"
                f" outdir={outdir}")
    rc = RC_SUCCESS
    exec_rt = None
    try:
        rc, exec_rt = main(workdir, outdir, dry_run)
    except Exception:
        logger.exception("uncaught exception in main:")
        rc = RC_UNCAUGHT_EXC
    end_ts = datetime.now()
    runtime = end_ts - start_ts
    rt_str = f"{runtime.seconds // 60}m{runtime.seconds % 60}s"
    logger.info(f"main() returned rc={rc}"
                f" seconds={runtime.seconds}"
                f" runtime={rt_str}")
    if exec_rt is not None:
        logger.info(f"exec_rt={exec_rt.seconds}")
    sys.exit(rc)


if __name__ == '__main__':
    cli()
