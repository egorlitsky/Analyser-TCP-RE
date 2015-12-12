#!/usr/bin/python3


import os
import sys
from scrtools.argsparser import parse_args
from scrtools.capturer import Capturer
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from time import sleep


def capture():
    # driver = webdriver.Chrome(os.path.expanduser("~/chromedriver"))
    driver = webdriver.Firefox()
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

def capture2():
    # driver = webdriver.Chrome(os.path.expanduser("~/chromedriver"))
    driver = webdriver.Firefox()
    driver.get("https://docs.python.org/3/")
    xpath = "//p[@class='biglink']/a[@href='faq/index.html']"
    element = driver.find_element_by_xpath(xpath)
    element.send_keys(Keys.RETURN)
    sleep(1)
    driver.close()

info2 = """
Capturing consists of visiting http://.python.org/,
taping 'pycon' in search tab and getting results
"""


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    Capturer(args.out_dir, capture, "1_python_org", info).capture()
    # Capturer(args.out_dir, capture, "1_python_org", info).capture()