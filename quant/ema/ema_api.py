import numpy as np

raw_values = []
ema_values = []

WINDOW = 20
ALPHA = 2 / (WINDOW + 1)
K = 2

def update_ema(value):
    global raw_values, ema_values

    raw_values.append(value)

    # --- EMA ---
    if len(ema_values) == 0:
        ema = value
    else:
        ema = ALPHA * value + (1 - ALPHA) * ema_values[-1]

    ema_values.append(ema)

    # keep window size fixed
    if len(raw_values) > WINDOW:
        raw_values.pop(0)
        ema_values.pop(0)

    # --- BOLLINGER ---
    std = np.std(raw_values) if len(raw_values) > 1 else 0

    upper = [e + K * std for e in ema_values]
    lower = [e - K * std for e in ema_values]

    # --- TREND ---
    trend = "stable"
    if value > upper[-1]:
        trend = "spike 🚨"
    elif value < lower[-1]:
        trend = "drop ⚠️"

    return {
        "ema": ema,
        "trend": trend,
        "history": {
            "raw": raw_values.copy(),
            "ema": ema_values.copy(),
            "upper": upper,
            "lower": lower
        }
    }