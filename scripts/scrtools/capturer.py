import os
import shlex
import shutil
import subprocess as sub
from contextlib import contextmanager
import datetime


@contextmanager
def tcpdump(output_file):
    cmd = "sudo tcpdump -i wlan0 " + "-U -w " + output_file
    args = shlex.split(cmd)
    proc = sub.Popen(args)
    try:
        yield
    finally:
        proc.terminate()


class Capturer:
    def __init__(self, parent_dir, capture_proc, tag, info):
        self._dir = parent_dir
        self._capture_proc = capture_proc
        self._tag = tag
        self._info = info

    def _clear_browser_cache(self):
        chromium_cache = "~/.cache/chromium/Default/"
        shutil.rmtree(
            os.path.expanduser(chromium_cache + "Cache"),
            ignore_errors=True
        )
        shutil.rmtree(
            os.path.expanduser(chromium_cache + "Media Cache"),
            ignore_errors=True
        )


    def _generate_info(self, filename):
        f = open(filename, "w+")
        f.write(self._info)
        f.close()

    def _capture_once(self):
        ts, *_ = str(datetime.datetime.now()).rpartition(".")
        ts = ts.replace(" ", "_")
        output_file_header = self._dir + "/" + self._tag + "_" + ts
        self._generate_info(output_file_header + ".txt")

        self._clear_browser_cache()
        with tcpdump(output_file_header + ".pcap"):
            self._capture_proc()

    def capture(self):
        self._capture_once()
        self._capture_once()