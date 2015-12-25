#!/usr/bin/python3


import os
import shlex
import subprocess as subpr


cache_sizes = [
    100, 200, 400, 800, 1200, 1600, 2000, 2500, 3000, 3500, 4000, 4500, 5000
]

hit_rate_header = b"Total hit rate: "


input_file_path = """\
./captures/SMIA\ 2011/SMIA_2011-10-10_08%3A03%3A19_CEST_632834000_file1.pcap"""
link = "ftp://download.iwlab.foi.se/dataset/smia2011/Network_traffic/"
output_file_path = "./captures/SMIA 2011/analysis_SMIA_2011_10_10_08.txt"


if __name__ == "__main__":
    if not os.path.isfile(input_file_path):
        err_msg = "No input file present: download {} from {}"
        raise ValueError(err_msg.format(input_file_path, link))

    f = open(output_file_path, "w")

    for cache_size in cache_sizes:
        cmd = "./bin/SnifferEx --vlan -f " + input_file_path
        cmd += " --cache_size " + str(cache_size)
        args = shlex.split(cmd)
        proc = subpr.Popen(args, stdout=subpr.PIPE)
        out, err = proc.communicate()
        _info, _header, hit_rate_value = out.rpartition(hit_rate_header)
        f.writelines(str(cache_size) + " " + hit_rate_value.decode("utf-8"))