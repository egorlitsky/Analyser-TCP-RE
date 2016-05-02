#!/usr/bin/python3


import sys
from script_runner import parse_args, run


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    run("download", False, args.sep)
