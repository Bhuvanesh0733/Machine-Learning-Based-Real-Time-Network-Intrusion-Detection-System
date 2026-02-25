import subprocess
import joblib
import numpy as np
model = joblib.load("models/ids_model.pkl")
scaler = joblib.load("models/scaler.pkl")
label_encoder = joblib.load("models/label_encoder.pkl")
def parse_line(line):
    try:
        parts = line.strip().split(",")
        if len(parts) < 4:
            return None
        src_ip = parts[0]
        dst_ip = parts[1]
        protocol = parts[2]
        length = int(parts[3])
        features = [1,1,1,length,0,0,0]
        return src_ip, dst_ip, protocol, np.array(features).reshape(1, -1)
    except:
        return None
def start_capture(interface="Wi-Fi"):
    cmd = [
        r"C:\Program Files\Wireshark\tshark.exe",
        "-i", interface,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len",
        "-E", "separator=,"
    ]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    for line in process.stdout:
        parsed = parse_line(line)
        if parsed:
            src_ip, dst_ip, protocol, features = parsed
            scaled = scaler.transform(features)
            prediction = model.predict(scaled)
            label = label_encoder.inverse_transform(prediction)
            yield {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "prediction": label[0]
            }