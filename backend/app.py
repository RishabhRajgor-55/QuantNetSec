from flask import Flask, request, jsonify, send_file
import joblib
import numpy as np
from datetime import datetime
import threading

from scapy.all import sniff
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from scapy.layers.inet import UDP

app2 = Flask(__name__)
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
def packet_sniffer():
    def process_packet(pkt):
        global latest_pkt, tcp_count, udp_count, total_packets, flows

        try:
            if not pkt.haslayer(IP):
                #print("No IP: ",pkt.summary())
                return

            total_packets += 1

            ip_layer = pkt[IP]
            proto = ip_layer.proto

            if proto == 6:
                tcp_count += 1
            elif proto == 17:
                udp_count += 1

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]

                key = (
                    ip_layer.src,
                    ip_layer.dst,
                    tcp_layer.sport,
                    tcp_layer.dport,
                    proto
                )

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

                if len(flows[key]) >= 10:
                    features = extract_features(flows[key], proto)
                    prediction = predict(features)
                    print(prediction)
                    latest_pkt["prediction"] = prediction
                    flows[key] = []

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
            print(pkt.summary())
            if total_packets % 10 == 0:
                log_packet(pkt)
        except Exception as e:
            print("Error processing packet:", e)
    while True:
        sniff(prn=process_packet, store = False, count=5)

def extract_features(flow, proto):
    packets = flow["packets"]
    sizes = [len(p) for p in packets]
    times = [p.time for p in packets]

    fwd_sizes = []
    bwd_sizes = []

    src_ip = packets[0][IP].src

    fwd = 0
    bwd = 0

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

    # ---------------- BASIC ----------------
    vector[0] = proto
    vector[1] = duration
    vector[2] = fwd
    vector[3] = bwd
    vector[4] = sum(fwd_sizes)
    vector[5] = sum(bwd_sizes)

    # ---------------- FWD ----------------
    vector[6] = max(fwd_sizes) if fwd_sizes else 0
    vector[7] = min(fwd_sizes) if fwd_sizes else 0
    vector[8] = np.mean(fwd_sizes) if fwd_sizes else 0
    vector[9] = np.std(fwd_sizes) if fwd_sizes else 0

    # ---------------- BWD ----------------
    vector[10] = max(bwd_sizes) if bwd_sizes else 0
    vector[11] = min(bwd_sizes) if bwd_sizes else 0
    vector[12] = np.mean(bwd_sizes) if bwd_sizes else 0
    vector[13] = np.std(bwd_sizes) if bwd_sizes else 0

    # ---------------- FLOW ----------------
    vector[14] = total_bytes / duration if duration > 0 else 0
    vector[15] = len(packets) / duration if duration > 0 else 0

    vector[16] = np.mean(iat)
    vector[17] = np.std(iat)
    vector[18] = np.max(iat)
    vector[19] = np.min(iat)

    # ---------------- FWD IAT ----------------
    vector[20] = sum(iat)
    vector[21] = np.mean(iat)
    vector[22] = np.std(iat)
    vector[23] = np.max(iat)
    vector[24] = np.min(iat)

    # ---------------- BWD IAT ----------------
    vector[25] = sum(iat)
    vector[26] = np.mean(iat)
    vector[27] = np.std(iat)
    vector[28] = np.max(iat)
    vector[29] = np.min(iat)

    # ---------------- FLAGS ----------------
    for p in packets:
        if p.haslayer(TCP):
            flags = p[TCP].flags
            vector[43] += int(flags & 0x01 != 0)
            vector[44] += int(flags & 0x02 != 0)
            vector[45] += int(flags & 0x04 != 0)
            vector[46] += int(flags & 0x08 != 0)
            vector[47] += int(flags & 0x10 != 0)
            vector[48] += int(flags & 0x20 != 0)

    # ---------------- PACKET STATS ----------------
    vector[38] = min(sizes)
    vector[39] = max(sizes)
    vector[40] = np.mean(sizes)
    vector[41] = np.std(sizes)
    vector[42] = np.var(sizes)

    # ---------------- RATIOS ----------------
    vector[51] = bwd / fwd if fwd > 0 else 0

    # ---------------- AVERAGES ----------------
    vector[52] = np.mean(sizes)
    vector[53] = np.mean(fwd_sizes) if fwd_sizes else 0
    vector[54] = np.mean(bwd_sizes) if bwd_sizes else 0

    # ---------------- SUBFLOW ----------------
    vector[61] = fwd
    vector[62] = sum(fwd_sizes)
    vector[63] = bwd
    vector[64] = sum(bwd_sizes)

    # ---------------- ACTIVE / IDLE ----------------
    active = flow["active_times"]
    idle = flow["idle_times"]

    if active:
        vector[69] = np.mean(active)
        vector[70] = np.std(active)
        vector[71] = max(active)
        vector[72] = min(active)

    if idle:
        vector[73] = np.mean(idle)
        vector[74] = np.std(idle)
        vector[75] = max(idle)
        vector[76] = min(idle)

    return vector

def predict(features):
    try:

        feature_array = np.array([features]).astype(float)

        pred = model.predict(feature_array)

        print("Raw Prediction:", pred)
        print("Features:", feature_array)

        prediction = le.inverse_transform(pred)[0]
        return prediction

    except Exception as e:
        print("Prediction error:", e)
        return "BENIGN"

def log_packet(pkt):
    try:
        if pkt.haslayer(IP):
            ip = pkt[IP]

            proto = "OTHER"
            sport, dport = "-", "-"

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            print(f"""
    [PACKET CAPTURED]
    Time      : {datetime.now().strftime("%H:%M:%S")}
    Source    : {ip.src}:{sport}
    Destination: {ip.dst}:{dport}
    Protocol  : {proto}
    Size      : {len(pkt)} bytes
    ----------------------------------
    """)

    except Exception as e:
        print("Logging error:", e)

@app2.route("/")
def home():
    return send_file("front2.html")

@app2.route('/live_packet')
def get_pkt():
    return jsonify({
        **latest_pkt,
        "total_packets": total_packets,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "prediction": latest_pkt.get("prediction", "Detecting...")
    })
if __name__ == "__main__":
    threading.Thread(target=packet_sniffer, daemon=True).start()
    app2.run(debug=True, use_reloader=False)