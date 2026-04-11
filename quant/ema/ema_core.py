class EMA:

    def __init__(self, alpha=0.3):
        self.alpha = alpha
        self.value = None

    def update(self, x):
        if self.value is None:
            self.value = x
        else:
            self.value = (1-self.alpha) * self.value + self.alpha * x
        return self.value