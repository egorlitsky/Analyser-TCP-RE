#!/usr/bin/python3


import os
import sys
from scrtools.argsparser import parse_args
from scrtools.capturer import Capturer


def capture():
    output_file = "__output__"
    url = "http://releases.ubuntu.com/14.04/ubuntu-14.04.3-desktop-amd64.iso"
    cmd = "wget " + url + " -O " + output_file
    os.system(cmd)
    os.system("rm " + output_file)


info = """
Capturing consists of downloading Ubuntu 14.04 distributive
from http://releases.ubuntu.com/14.04/ubuntu-14.04.3-desktop-amd64.iso
"""

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "ubuntu_14.04", info).capture()