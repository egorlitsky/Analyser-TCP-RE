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
    driver.get("http://www.stackoverflow.com")
    xpath = "//div[@id='tabs']/a[@data-value='hot']"
    element = driver.find_element_by_xpath(xpath)
    element.send_keys(Keys.RETURN)
    sleep(1)
    driver.close()

info = """
Capturing consists of visiting http://www.stackoverflow.com
and selecting 'hot' tab on starting page
"""

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "stackoverflow_com", info).capture()