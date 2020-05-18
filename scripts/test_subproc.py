import multiprocessing as mp
import os
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from pipeline_worker import RunUnpack, Subprocess

repr(RunUnpack)
repr(Subprocess)


@contextmanager
def tempfifo(_workdir):
    fifo_path = Path(_workdir) / "fifo"
    print(fifo_path)
    try:
        os.mkfifo(fifo_path)
        print("made fifo")
        yield fifo_path
    finally:
        if fifo_path.exists():
            os.unlink(fifo_path)
        print("unlink fifo")


with TemporaryDirectory() as workdir:
    print(f"workdir: {workdir}")
    with tempfifo(workdir) as fifo_fn:
        def write_fifo(fifo_fn, _wait):
            time.sleep(_wait)
            with open(fifo_fn, 'wb') as fd:
                len(fd.name)
                pass

        child = mp.Process(target=write_fifo, args=(fifo_fn, 5,))
        child.start()
        print("child started")

        print(f"opening fifo {fifo_fn}")
        with open(fifo_fn, 'rb') as fifo_fd:
            print("opened fifo")
        print("child done")
        child.join()
        print("child join")
        time.sleep(1)
        print("short sleep")
