from .volatility_core import Volatility
from .volatility_storage import VolatilityStorage
from .volatility_analyzer import analyze

vol_calc = Volatility()
storage = VolatilityStorage()

def update_volatility(value):

    vol = vol_calc.update(value)
    storage.add(vol)

    trend = analyze(storage.get())

    return {
        "volatility": vol,
        "vol_trend": trend,
        "vol_history": storage.get()
    }