#!/usr/bin/python3


import sys
from captools.argsparser import parse_args
from captools.capturer import capture_all
from selenium.webdriver.common.keys import Keys
from time import sleep


def action1(driver):
    xpath = "//div[@id='tabs']/a[@data-value='hot']"
    element = driver.find_element_by_xpath(xpath)
    element.send_keys(Keys.RETURN)
    sleep(1)

info1 = """\
Capturing consists of visiting http://www.stackoverflow.com
and selecting 'hot' tab on starting page
"""


def action2(driver):
    driver.get("http://www.lenta.ru/")
    sleep(1)

info2 = """\
Capturing consists of reading one article on www.lenta.ru
and returning to the main page of the site
"""


def action3(driver):
    xpath = "//a[@href='http://pikabu.ru/best']"
    driver.find_element_by_xpath(xpath).click()
    sleep(5)


info3 = """\
Capturing consists of visiting pikabu.ru start page and
clicking on 'best' tab
"""


def action4(driver):
    sleep(2)
    xpath = "//a[@href='http://habrahabr.ru/top/']"
    driver.find_element_by_xpath(xpath).click()
    sleep(5)

info4 = """\
Capturing consists of visiting habrahabr.ru start page and
clicking on 'best' tab
"""


def action5(driver):
    xpath = "//a[@href='/dota-2/guides']"
    driver.find_element_by_xpath(xpath).click()
    sleep(4)
    # xpath1 = "//div[contains(.,'Discussion')]"
    # driver.find_element_by_xpath(xpath1).click()
    # sleep(5)

info5 = """\
Capturing consists of visiting www.dotafire.com site,
choosing 'Hero Guides' tab and sorting guides by 'Discussion'
"""


data = [
    ("http://www.stackoverflow.com", action1, info1),
    ("http://www.lenta.ru/news/2015/12/15/italy_pipeline/", action2, info2),
    ("http://www.pikabu.ru/", action3, info3),
    ("http://www.habrahabr.ru/", action4, info4),
    ("http://www.dotafire.com/", action5, info5)
]


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    capture_all(args.out_dir, data)
