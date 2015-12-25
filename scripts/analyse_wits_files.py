#!/usr/bin/python3


import os
import shlex
import subprocess as subpr


cache_sizes = [
    100, 200, 400, 800, 1200, 1600, 2000, 3000, 4000, 5000
]

hit_rate_header = b"Total hit rate: "

working_dir = "./captures/WITS/"
output_file = "./captures/WITS/analysis.txt"
link = "ftp://wits.cs.waikato.ac.nz/ispdsl/2"


if __name__ == "__main__":
    if not os.path.isdir(working_dir):
        raise ValueError("No dir exists: {}".format(working_dir))

    f = open(output_file, "w")

    pcap_files_cmd = ""
    for entry in os.listdir(working_dir):
        if os.path.isfile(working_dir + entry) and entry.endswith(".pcap"):
            pcap_files_cmd += " -f " + working_dir + entry

    if pcap_files_cmd == "":
        err_msg = "No files in {} dir: download any from {} and convert to pcap"
        raise ValueError(err_msg.format(working_dir, link))

    for cache_size in cache_sizes:
        print("Testing with {} MB cache size".format(cache_size))
        cmd = "./bin/SnifferEx --vlan " + pcap_files_cmd
        cmd += " --cache_size " + str(cache_size)
        args = shlex.split(cmd)
        proc = subpr.Popen(args, stdout=subpr.PIPE)
        out, err = proc.communicate()
        _info, _header, hit_rate_value = out.rpartition(hit_rate_header)
        f.writelines(str(cache_size) + " " + hit_rate_value.decode("utf-8"))