#!/usr/bin/python3


import os
import random
import shlex
import shutil
import subprocess as subpr
from script_runner import run, out_dir_temp as generated_dir


# generated_dir = "./captures/generated_temp/"
output_filename = "statistics.txt"

scripts_prefs = ["browser", "video", "download"]
files_number = 3

cache_size = 2000 # in MB
cache_flag = " --cache_size " + str(cache_size)
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


def generate(script_pref):
    curr_dir = generated_dir + script_pref + "/"
    run(script_pref, True)

    acc = []
    for folder in os.listdir(curr_dir):
        subdir = curr_dir + folder + "/"
        if not os.path.isdir(subdir):
            continue

        pcap_files = [
            entry for entry in os.listdir(subdir)\
            if os.path.isfile(subdir + entry) and\
            entry.endswith(".pcap")
        ]
        if len(pcap_files) != 2:
            raise ValueError("Generation failed!")

        files_flag = "".join(" -f " + subdir + entry for entry in pcap_files)
        args = shlex.split("sudo ./bin/SnifferEx" + files_flag + cache_flag)
        proc = subpr.Popen(args, stdout=subpr.PIPE)

        out, err = proc.communicate()
        _info, _header, hit_rate = out.rpartition(hit_rate_header)
        acc.append(float(hit_rate))
    return acc


def calc(script_pref):
    curr_dir = generated_dir + script_pref + "/"
    hit_rates = []
    
    for i in range(files_number):
        hit_rates.extend(generate(script_pref))
        for entry in os.listdir(curr_dir):
            if os.path.isdir(curr_dir + entry):
                shutil.rmtree(curr_dir + entry)

    e_n, s_n = calc_mean_var(hit_rates)
    f = open(curr_dir + output_filename, "w")
    f.writelines(
        "Number of experiments: " + str(len(hit_rates)) +
        "\nMean: " + str(e_n) +
        "\nVar: " + str(s_n)
    )


if __name__ == "__main__":
    for script_pref in scripts_prefs:
        calc(script_pref)