#!/usr/bin/python3


import sys
from captools.argsparser import parse_args
from captools.capturer import capture_all
from time import sleep


def action1(driver):
    sleep(2 * 60 + 35)

info1 = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official trailer on youtube
"""


def action2(driver):
    sleep(1 * 60 + 59)

info2 = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official teaser on youtube
"""


def action3(driver):
    sleep(3 * 60 + 15 + 30 + 10)

info3 = """
Capturing consists of watching episode of 'CS:GO' stream of g5taz
streamer on twitch, recorded on 7th on December, 2015,
time includes 30 sec interval for advertisement
"""


def action4(driver):
    sleep(2 * 60 + 48 + 5)

info4 = """
Capturing consists of watching episode of JArroLive's stream
on hitbox, playing 'Euro Truck Simulator 2'
"""


def action5(driver):
    sleep(31 + 5)

info5 = """
Capturing consists of watching video with turkeys attacking mailman,
on rutube
"""


data = [
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1),
    # ("http://www.youtube.com/watch?v=ngElkyQ6Rhs", action2, info2),
    ("http://www.twitch.tv/g5taz/v/28741967", action3, info3),
    ("http://www.hitbox.tv/video/759363/description", action4, info4),
    ("http://www.rutube.ru/video/7f5d4dedad58e0c4dd2b488b9aca2d0b/", action5, info5)
]


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    capture_all(args.out_dir, data)
