#!/usr/bin/python3
# vim: ts=4 expandtab

"""Self care commands"""

from __future__ import annotations

import random

import bot.commands

BIG_REMINDERS = [
    "take your meds",
    "check your medication",
]

REGULAR_THINGS = [
    "eat a meal",
    "have something to eat",
    "drink some water",
    "grab a refreshing drink",
    "stretch your body",
    "raise you heart rate",
]

DAILY_THINGS = [
    "reaching out to someone",
    "tend to a living/growing thing",
    "take a shower or bath",
    "clean one space or surface",
]

FORMATS = [
    "Looking after yourself is key: {reminder}, {regular}, and consider {daily}. 💜",
    "Looking after yourself is key: {reminder}, {regular}, and consider {daily}. 💜",
    "Looking after yourself is key: {reminder}, {regular}, and consider {daily}. 💜",
    "Time to {regular}? Maybe {daily}? Also, {reminder}. 🧡",
    "In the words of dear community member Baron Samedi: meds reminder for those who may need it.",
    "Remember to {reminder}",
]


class SelfCare(bot.commands.SimpleCommand):
    """Reminds our dear friends to look after themselves."""

    def __init__(self) -> None:
        super().__init__("selfcare", SelfCare.message)

    @staticmethod
    def message() -> str:
        layout = random.choice(FORMATS)
        reminder = random.choice(BIG_REMINDERS)
        regular = random.choice(REGULAR_THINGS)
        daily = random.choice(DAILY_THINGS)

        return layout.format(reminder=reminder, regular=regular, daily=daily)
