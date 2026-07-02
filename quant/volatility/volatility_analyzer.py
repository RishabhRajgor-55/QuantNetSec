def analyze(vol_values):

    if len(vol_values) < 5:
        return "stable"

    if vol_values[-1] > vol_values[-5] * 1.5:
        return "high volatility 🚨"

    elif vol_values[-1] < vol_values[-5] * 0.7:
        return "low volatility 💤"

    return "normal"