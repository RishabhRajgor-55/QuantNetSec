# QuantNetSec

A real-time network intrusion detection system that combines statistical signal-processing techniques (EMA, rolling volatility, Z-score deviation, Shannon entropy) with a machine learning classifier to flag suspicious traffic — visualized on a live dashboard.

Built for IT254, NITK Surathkal, by Group 6 (Hradayastha Thakran, Rishabh Hiten Rajgor, Saurabh).

## Dashboard

![Dashboard overview](docs/images/dashboard-overview.png)

![Dashboard analytics view](docs/images/dashboard-analytics.png)

## How it works

- A packet sniffer (Scapy) captures live traffic and extracts per-flow features (packet size, duration, protocol mix, forward/backward byte counts).
- A trained ML model (Random Forest, via `model.pkl`) classifies each flow as normal or suspicious.
- In parallel, a quantitative layer scores traffic behavior independent of the ML model:
  - **Z-score deviation** — flags a feature as anomalous when it drifts more than ~2–3 standard deviations from its rolling baseline.
  - **Shannon entropy** — tracks how concentrated vs. spread out protocol/traffic distribution is; sudden entropy shifts (e.g. during a DDoS) get flagged.
  - **EMA + Bollinger Bands / rolling volatility** — smooths traffic volume over time and highlights bursts.
- Results stream to the frontend in real time over WebSockets (Flask-SocketIO) and render as live charts, KPIs, and a packet log table.

## Tech stack

Python, Flask, Flask-SocketIO, Scapy, scikit-learn, pandas, numpy, joblib — HTML/CSS/JS frontend with Chart.js-style live visualizations.

## Project structure

```
QuantNetSec/
├── app.py                  # main entry point — run this
├── index_mod.html          # dashboard frontend served by app.py
├── index.html
├── columns.py
├── packet_flow_gen/        # synthetic traffic generators for testing
├── quant/
│   ├── ema/                 # EMA + Bollinger Band analysis
│   └── volatility/           # rolling volatility analysis
├── backend/                # earlier backend-only version (not used to run the demo)
├── requirements.txt
└── model.pkl, scaler.pkl, label_encoder.pkl, features.pkl   # NOT in repo — see Setup below
```

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/RishabhRajgor-55/QuantNetSec.git
cd QuantNetSec
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Download the trained model files from Kaggle

The trained model (`model.pkl`, `scaler.pkl`, `label_encoder.pkl`, `features.pkl`) is hosted on Kaggle instead of GitHub since it's too large for a normal git push.

**Kaggle dataset:** `https://www.kaggle.com/datasets/rishabhrajgor/quantnetsec-models`

**Download manually:**
1. Open the Kaggle dataset link above.
2. Click **Download** to get the archive.
3. Unzip it and copy `model.pkl`, `scaler.pkl`, `label_encoder.pkl`, and `features.pkl` into the **root of this repo** — the same folder as `app.py`.

### 4. Run the app

Live packet sniffing needs elevated permissions:

```bash
# macOS / Linux
sudo venv/bin/python app.py

# Windows (run terminal as Administrator, and make sure Npcap is installed:
# https://npcap.com/#download)
python app.py
```

Then open **http://localhost:5000** in your browser. The dashboard will start streaming live traffic stats, predictions, and risk scores as packets are captured.

> **Note:** Scapy requires a packet-capture backend. On Windows, install [Npcap](https://npcap.com/#download) first. On Linux/macOS, running with `sudo` is usually enough; alternatively grant the Python binary capture permissions with `setcap cap_net_raw,cap_net_admin=eip $(which python3)`.

## Troubleshooting

| Issue | Fix |
|---|---|
| `FileNotFoundError: model.pkl` | Model files aren't in the repo root — see Setup step 3 |
| `Permission denied` / no packets captured | Run with `sudo` (Linux/macOS) or install Npcap and run as Administrator (Windows) |
| Blank dashboard, no live updates | Check the terminal for sniffer errors — some network interfaces (e.g. VPN-only machines) may need `sniff(iface="...")` set explicitly in `app.py` |

## Contributors

Rishabh Hiten Rajgor

Hradayastha Thakran

Saurabh