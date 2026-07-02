class EMAStorage:
    def __init__(self, max_len=20):
        self.max_len = max_len
        self.raw_values = []
        self.ema_values = []

    def add(self, raw, ema):
        self.raw_values.append(raw)
        self.ema_values.append(ema)

        if len(self.raw_values) > self.max_len:
            self.raw_values.pop(0)
            self.ema_values.pop(0)

    def get(self):
        return {
            'raw': self.raw_values,
            'ema': self.ema_values
        }