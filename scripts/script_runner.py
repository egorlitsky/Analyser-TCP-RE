import argparse
import os


out_dir_const = "./captures/generated/"
out_dir_temp = "./captures/generated_temp/"
scripts_dir = os.path.join(os.getcwd(), "./scripts/capturing_scripts/")


# argument parser for scripts that invoke 'run'
# function with certain parameters
def parse_args(args):
    parser = argparse.ArgumentParser(
        description="Process args to runner script"
    )
    parser.add_argument("--sep", dest="sep", action="store_true")
    parser.add_argument("--comb", dest="sep", action="store_false")
    parser.set_defaults(sep=True)
    return parser.parse_args(args)


# function ensures that output directory contains
# subfolders for corresponding content type
def run(cont_type, temp, sep_f):
    out_dir = out_dir_temp if temp else out_dir_const

    for script in os.listdir(scripts_dir):
        if script.startswith(cont_type):
            curr_out_dir = out_dir + script[: -1 * len(".py")]
            if not os.path.exists(curr_out_dir):
                os.makedirs(curr_out_dir)
            cmd = "sudo ./scripts/capturing_scripts/" + script
            sep_str = " --sep" if sep_f else " --comb"
            os.system(cmd + " --out_dir " + curr_out_dir + sep_str)
