#!/usr/bin/python3


import os


out_dir = "./captures/generated/"

scripts_dir = os.path.join(os.getcwd(), "./scripts/capturing_scripts/")
for script in os.listdir(scripts_dir):
    if script.startswith("download_"):
        curr_out_dir = out_dir + script[len("download_"):-3]
        os.system("mkdir -p " + curr_out_dir)
        cmd = "sudo ./scripts/capturing_scripts/" + script
        os.system(cmd + " --out_dir " + curr_out_dir)