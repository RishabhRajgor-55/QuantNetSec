import numpy as np

class Volatility:
    def __init__(self, window=20):
        self.window = window
        self.values = []

    def update(self, x):
        self.values.append(x)

        if len(self.values) > self.window:
            self.values.pop(0)

        if len(self.values) < 2:
            return 0

        return np.std(self.values)