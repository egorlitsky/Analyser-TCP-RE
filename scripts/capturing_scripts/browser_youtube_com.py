#!/usr/bin/python3


import os
import sys
from scrtools.argsparser import parse_args
from scrtools.capturer import Capturer
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep


def capture():
    driver = webdriver.Firefox()
    driver.get("http://www.youtube.com/watch?v=sGbxmsDFVnE/")
    sleep(2 * 60 + 35)
    driver.close()

info = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official trailer on youtube
"""


def capture2():
    driver = webdriver.Firefox()
    driver.get("http://www.youtube.com/watch?v=ngElkyQ6Rhs")
    sleep(1 * 60 + 59)
    driver.close()

info2 = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official teaser on youtube
"""



if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "1_youtube_com", info).capture()
    Capturer(args.out_dir, capture2, "2_youtube_com", info2).capture()