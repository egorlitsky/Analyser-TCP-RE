#!/usr/bin/python3


import os


out_dir = "./captures/generated/"

non_execs = ["capturer.py", "argsparser.py"]
scripts_dir = os.path.join(os.getcwd(), "./scripts/")
for script in os.listdir(scripts_dir):
    if script.endswith(".py") and script not in non_execs:
        curr_out_dir = out_dir + script[:-3]
        os.system("mkdir -p " + curr_out_dir)
        os.system("sudo ./scripts/" + script + " --out_dir " + curr_out_dir)