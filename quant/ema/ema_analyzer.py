def analyze(ema_values):
    if len(ema_values) < 5:
        return {
            "trend": "stable",
            "trend_flag": False
        }

    if ema_values[-1] > ema_values[-5]:
        return {
            "trend": "increasing",
            "trend_flag": True
        }
    elif ema_values[-1] < ema_values[-5]:
        return {
            "trend": "decreasing",
            "trend_flag": False
        }
    else:
        return {
            "trend": "stable",
            "trend_flag": False
        }