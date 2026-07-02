class VolatilityStorage:
    def __init__(self, max_len=20):
        self.values = []

    def add(self, v):
        self.values.append(v)
        if len(self.values) > 20:
            self.values.pop(0)

    def get(self):
        return self.values