import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from flask import Flask, jsonify, send_file
import joblib
import numpy as np
from datetime import datetime
import threading
import time
import pandas as pd
from flask_socketio import SocketIO
from scapy.all import sniff
from scapy.layers.inet import TCP, IP, UDP

from quant.ema.ema_api import update_ema

# ---------------- INIT ----------------
app2 = Flask(__name__)
socketio = SocketIO(app2, cors_allowed_origins="*", async_mode='threading')

lock = threading.Lock()

latest_pkt = {
    "prediction": "Detecting...",
    "timestamp": "Start",
    "packet_size": 0,
    "src_ip": "-",
    "dst_ip": "-",
    "protocol": 0,
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0
}

tcp_count = 0
udp_count = 0
total_packets = 0
flows = {}

model = joblib.load('intrusion_model.pkl')
le = joblib.load('label_encoder.pkl')

last_emit_time = 0  # for throttling


# ---------------- PACKET SNIFFER ----------------
def packet_sniffer():

    def process_packet(pkt):
        global latest_pkt, tcp_count, udp_count, total_packets, flows, last_emit_time

        try:
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            proto = ip_layer.proto

            # ---------- COUNTERS ----------
            with lock:
                total_packets += 1
                if proto == 6:
                    tcp_count += 1
                elif proto == 17:
                    udp_count += 1

            # ---------- FLOW LOGIC ----------
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]

                key = (
                    ip_layer.src,
                    ip_layer.dst,
                    tcp_layer.sport,
                    tcp_layer.dport,
                    proto
                )

                with lock:
                    if key not in flows:
                        flows[key] = {
                            "packets": [],
                            "start_time": pkt.time,
                            "last_time": pkt.time,
                            "active_times": [],
                            "idle_times": [],
                            "last_active": pkt.time
                        }

                    flow = flows[key]
                    flow["packets"].append(pkt)

                    now = pkt.time

                    if now - flow["last_active"] > 1:
                        flow["idle_times"].append(now - flow["last_active"])
                    else:
                        flow["active_times"].append(now - flow["last_time"])

                    flow["last_active"] = now
                    flow["last_time"] = now

                # ---------- ML PREDICTION ----------
                if len(flow["packets"]) >= 10:
                    features = extract_features(flow, proto)
                    prediction = predict(features)

                    with lock:
                        latest_pkt["prediction"] = prediction
                        del flows[key]

            # ---------- UPDATE PACKET ----------
            with lock:
                latest_pkt.update({
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "protocol": proto,
                    "packet_size": len(pkt),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "total_packets": total_packets,
                    "tcp_count": tcp_count,
                    "udp_count": udp_count
                })

            # ---------- EMA ----------
            ema_result = update_ema(latest_pkt["packet_size"])
            latest_pkt["ema"] = ema_result["ema"]
            latest_pkt["trend"] = ema_result["trend"]
            latest_pkt["ema_history"] = ema_result["history"]

            # ---------- WEBSOCKET EMIT (THROTTLED) ----------
            if time.time() - last_emit_time > 0.2:
                socketio.emit('packet_update', dict(latest_pkt))  # send copy
                last_emit_time = time.time()

        except Exception as e:
            print("Error:", e)

    sniff(prn=process_packet, store=False)


# ---------------- FEATURE EXTRACTION ----------------
def extract_features(flow, proto):
    packets = flow["packets"]
    sizes = [len(p) for p in packets]
    times = [p.time for p in packets]

    fwd_sizes, bwd_sizes = [], []
    src_ip = packets[0][IP].src

    fwd = bwd = 0

    for p in packets:
        if p[IP].src == src_ip:
            fwd += 1
            fwd_sizes.append(len(p))
        else:
            bwd += 1
            bwd_sizes.append(len(p))

    duration = times[-1] - times[0] if len(times) > 1 else 0
    total_bytes = sum(sizes)

    iat = np.diff(times) if len(times) > 1 else [0]

    vector = [0] * 77

    # BASIC
    vector[0] = proto
    vector[1] = duration
    vector[2] = fwd
    vector[3] = bwd
    vector[4] = sum(fwd_sizes)
    vector[5] = sum(bwd_sizes)

    # FWD
    if fwd_sizes:
        vector[6] = max(fwd_sizes)
        vector[7] = min(fwd_sizes)
        vector[8] = np.mean(fwd_sizes)
        vector[9] = np.std(fwd_sizes)

    # BWD
    if bwd_sizes:
        vector[10] = max(bwd_sizes)
        vector[11] = min(bwd_sizes)
        vector[12] = np.mean(bwd_sizes)
        vector[13] = np.std(bwd_sizes)

    # FLOW
    vector[14] = total_bytes / duration if duration > 0 else 0
    vector[15] = len(packets) / duration if duration > 0 else 0

    vector[16] = np.mean(iat)
    vector[17] = np.std(iat)
    vector[18] = np.max(iat)
    vector[19] = np.min(iat)

    # FLAGS
    for p in packets:
        if p.haslayer(TCP):
            flags = p[TCP].flags
            vector[43] += int(flags & 0x01 != 0)
            vector[44] += int(flags & 0x02 != 0)
            vector[45] += int(flags & 0x04 != 0)
            vector[46] += int(flags & 0x08 != 0)
            vector[47] += int(flags & 0x10 != 0)
            vector[48] += int(flags & 0x20 != 0)

    # PACKET STATS
    vector[38] = min(sizes)
    vector[39] = max(sizes)
    vector[40] = np.mean(sizes)
    vector[41] = np.std(sizes)
    vector[42] = np.var(sizes)

    # RATIOS
    vector[51] = bwd / fwd if fwd > 0 else 0

    # AVERAGES
    vector[52] = np.mean(sizes)
    vector[53] = np.mean(fwd_sizes) if fwd_sizes else 0
    vector[54] = np.mean(bwd_sizes) if bwd_sizes else 0

    return vector


# ---------------- PREDICTION ----------------
def predict(features):
    try:
        feature_array = np.array([features]).astype(float)
        pred = model.predict(feature_array)
        prediction = le.inverse_transform(pred)[0]
        return prediction
    except Exception as e:
        print("Prediction error:", e)
        return "BENIGN"


# ---------------- ROUTES ----------------
@app2.route("/")
def home():
    return send_file("index_mod.html")


@app2.route("/live_packet")
def get_pkt():
    return jsonify(latest_pkt)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    threading.Thread(target=packet_sniffer, daemon=True).start()
    socketio.run(app2, debug=True, use_reloader=False)