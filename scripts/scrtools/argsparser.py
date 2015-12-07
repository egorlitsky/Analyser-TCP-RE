import argparse


def parse_args(args):
    parser = argparse.ArgumentParser(
        description="Process args to generator scripts"
    )
    parser.add_argument("--out_dir", help="output dir for generated files")
    return parser.parse_args(args)