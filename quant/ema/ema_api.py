from quant.ema.ema_core import EMA
from quant.ema.ema_storage import EMAStorage
from quant.ema.ema_analyzer import analyze

ema_model = EMA(alpha=0.3)
storage = EMAStorage()

def update_ema(value):
    ema_val = ema_model.update(value)
    storage.add(value, ema_val)
    analysis = analyze(storage.ema_values)

    return {
        "ema":float(ema_val),
        "trend": analysis["trend"],
        "trend_flag": analysis["trend_flag"],
        "history":storage.get()
    }