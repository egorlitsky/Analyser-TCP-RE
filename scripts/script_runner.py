import os


out_dir_const = "./captures/generated/"
out_dir_temp = "./captures/generated_temp/"
scripts_dir = os.path.join(os.getcwd(), "./scripts/capturing_scripts/")


def run(prefix, temp):
    out_dir = out_dir_temp if temp else out_dir_const

    for script in os.listdir(scripts_dir):
        if script.startswith(prefix):
            curr_out_dir = out_dir + script[: -1 * len(".py")]
            if not os.path.exists(curr_out_dir):
                os.makedirs(curr_out_dir)
            cmd = "sudo ./scripts/capturing_scripts/" + script
            os.system(cmd + " --out_dir " + curr_out_dir)
