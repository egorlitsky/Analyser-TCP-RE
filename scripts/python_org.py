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
    driver.get("http://www.python.org")
    element = driver.find_element_by_name("q")
    element.send_keys("pycon")
    element.send_keys(Keys.RETURN)
    sleep(2)
    driver.close()

info = """
Capturing consists of visiting http://www.python.org/,
taping 'pycon' in search tab and getting results
"""

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "python_org", info).capture()