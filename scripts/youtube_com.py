#!/usr/bin/python3


import os
import sys
from scrtools.argsparser import parse_args
from scrtools.capturer import Capturer
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep


def capture():
    driver = webdriver.Chrome(os.path.expanduser("~/chromedriver"))
    driver.get("http://www.youtube.com/watch?v=sGbxmsDFVnE/")
    sleep(2 * 60 + 35)
    driver.close()

info = """
Capturing consists of watching 'Star Wars: The Force Awakens'
trailer on youtube
"""

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "youtube_com", info).capture()