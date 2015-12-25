#!/usr/bin/python3


import os
import random
import shlex
import subprocess as subpr
from script_runner import out_dir_const as generated_dir

cache_size = 2000 # in MB
files_number = 3

output_filename = "statistics.txt"

hit_rate_header = b"Total hit rate: "

def calc_mean_var(values):
    e_n, s_n = 0, 0
    n = len(values)
    for value in values:
        e_n += value
        s_n += value * value
    e_n = e_n / n
    s_n = s_n / n - e_n * e_n
    return e_n, s_n


def run_analyse(dir):
    f = open(dir + output_filename, "w")
    hit_rates = []

    for entry in os.listdir(dir):
        sub_dir = dir + entry + "/"
        if not os.path.isdir(sub_dir):
            continue

        used = set()
        pcap_files = [
            sub_dir + f for f in os.listdir(sub_dir) if os.path.isfile(sub_dir + f) and\
            f.endswith(".pcap")
        ]
        info_files = [
            sub_dir + f for f in os.listdir(sub_dir) if os.path.isfile(sub_dir + f) and\
            f.endswith(".txt")
        ]
        file_sets = [
            (pcap, pcap[:-1 * len(".pcap")] + ".txt") for pcap in pcap_files\
            if pcap[:-1 * len(".pcap")] + ".txt" in info_files
        ]

        if len(file_sets) != len(pcap_files) or\
           len(file_sets) != len(info_files):
            raise ValueError("Not enough files in {}".format(sub_dir))
        while len(used) < max(files_number, len(pcap_files) // 2):
            p1, i1 = random.choice(file_sets)
            p2, i2 = random.choice(file_sets)

            if p1 != p2 and (p1, p2) not in used and (p2, p1) not in used:
                with open(i1) as f1:
                    with open(i2) as f2:
                        if f1.read() != f2.read():
                            continue

                cmd = "./bin/SnifferEx -f " + p1 + " -f " + p2
                cmd += " --cache_size " + str(cache_size)
                args = shlex.split(cmd)
                proc = subpr.Popen(args, stdout=subpr.PIPE)
                out, err = proc.communicate()
                _info, _header, hit_rate = out.rpartition(hit_rate_header)

                f.writelines(
                    "Analysed " + p1 + " and " + p2 +
                    "\nHit rate: " + hit_rate.decode("utf-8") + "\n"
                )
                used.add((p1, p2))
                hit_rates.append(float(hit_rate))

    e_n, s_n = calc_mean_var(hit_rates)
    f.writelines("Mean: " + str(e_n) + "\nVar: " + str(s_n))



if __name__ == "__main__":
    for dir in os.listdir(generated_dir):
        if os.path.isdir(generated_dir + dir + "/"):
            print("Analysing " + generated_dir + dir + "/")
            run_analyse(generated_dir + dir + "/")