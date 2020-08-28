#!/usr/bin/env python3
import random
import time

from pwncat.modules import BaseModule, List, Argument, Result


class TestResult(Result):
    def __init__(self, category, value):
        self._category = category
        self.value = value

        if random.randint(1, 10) > 5:
            self._description = "This is a long description of the value " + str(
                self.value
            )
        else:
            self._description = None

    @property
    def title(self):
        return "Test Result: " + str(self.value)

    @property
    def category(self):
        return self._category

    @property
    def description(self):
        return self._description


class Module(BaseModule):
    """  """

    ARGUMENTS = {"arg1": Argument(type=int)}

    def run(self, arg1):
        categories = ["Category 1", "Category 2", "Category 3"]
        values = [random.randint(1, 100) for _ in range(arg1)]

        for i in values:
            yield TestResult(random.choice(categories), i)
            time.sleep(1)
