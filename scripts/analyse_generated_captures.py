#!/usr/bin/python3


import datetime
import os
import random
from script_runner import out_dir_const as scripts_dir


out_folder = "_results"


def same_content(comment, filepath_to_comp):
    with open(filepath_to_comp) as content_file:
        return comment == content_file.read()


def rec_analyse(dir):
    f = False
    for entry in os.listdir(dir):
        if os.path.isdir(dir + entry) and entry != out_folder:
            rec_analyse(dir + entry + "/")
            f = True

    while not f:
        try:
            rand_file = random.choice(os.listdir(dir))
        except IndexError:
            return

        if os.path.isfile(dir + rand_file):
            f = True
            file_to_analyse = None
            file_with_comments = None
            if rand_file.endswith(".txt"):
                file_with_comments = rand_file
                file_to_analyse = rand_file[:-1 * len("txt")] + "pcap"
            elif rand_file.endswith(".pcap"):
                file_to_analyse = rand_file
                file_with_comments = rand_file[:-1 * len("pcap")] + "txt"

            if not os.path.isfile(dir + file_to_analyse) or\
            not os.path.isfile(dir + file_with_comments):
                err_msg = "Incompleted capture file was found : {}"
                raise ValueError(err_msg.format(rand_file))

            comments = ""
            with open(dir + file_with_comments) as content_file:
                comments = content_file.read()

            for i in range(1000):
                entry = random.choice(os.listdir(dir))
                if entry != file_with_comments and entry.endswith(".txt") and\
                same_content(comments, dir + entry):
                    os.system("mkdir -p " + dir + out_folder)
                    ts, *_ = str(datetime.datetime.now()).rpartition(".")
                    ts = ts.replace(" ", "_")
                    out_file = dir + out_folder + "/analyse_output_" + ts + ".txt"

                    next_file_to_analyse = entry[:-1 * len("txt")] + "pcap"
                    cmd = "./bin/SnifferEx -f " + dir + file_to_analyse
                    cmd += " -f " + dir + next_file_to_analyse + " --cache_size 500"
                    cmd += " -o " + out_file
                    os.system(cmd)
                    break


if __name__ == "__main__":
    rec_analyse(scripts_dir)