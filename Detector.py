import numpy as np
from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import threading
import socket
from datetime import datetime
from tensorflow.keras.models import load_model
from scapy.all import sniff
import queue
import time
import pandas as pd
import joblib
import logging
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from collections import defaultdict

# Set up logging
logging.basicConfig(filename='detections.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Load the trained Keras model and preprocessing pipeline
try:
    model = load_model('my_model.h5')
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    exit(1)

try:
    ct = joblib.load('column_transformer.pkl')
    scaler = joblib.load('scaler.pkl')
    num_col = joblib.load('num_col.pkl')  # Load the numerical columns list
    print("Preprocessing pipeline and columns loaded successfully")
    print("Loaded num_col:", num_col)
except Exception as e:
    print(f"Error loading preprocessing pipeline: {e}")
    exit(1)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store detections in memory (limited to 100 for performance)
detections = []
detections_lock = threading.Lock()

# Queue for packet data (thread-safe)
packet_queue = queue.Queue()

# Attack types mapping (matches the 10 classes from minorproject3.ipynb)
attack_types = {
    0: "normal", 1: "generic", 2: "fuzzers", 3: "Exploits", 4: "Dos",
    5: "Reconaissance", 6: "Backdoor", 7: "Analysis", 8: "Shellcode", 9: "Worms"
}

# Define categorical columns
cat_col = ['proto', 'service', 'state']

# Flow tracking for dynamic feature computation
flow_data = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start_time': 0})

# Function to extract features from a single packet
def extract_features(packet):
    features = {
        'proto': 'tcp', 'service': 'None', 'state': 'INT',  # Default to valid proto
        'dur': 0.0, 'sbytes': 0, 'dbytes': 0, 'sttl': 0, 'dttl': 0, 'sloss': 0, 'dloss': 0,
        'Sload': 0.0, 'Dload': 0.0, 'Spkts': 0, 'Dpkts': 0, 'swin': 0, 'dwin': 0, 'stcpb': 0,
        'dtcpb': 0, 'smeansz': 0, 'dmeansz': 0, 'trans_depth': 0, 'res_bdy_len': 0, 'Sjit': 0.0,
        'Djit': 0.0, 'Stime': 0.0, 'Ltime': 0.0, 'Sintpkt': 0.0, 'Dintpkt': 0.0, 'tcprtt': 0.0,
        'synack': 0.0, 'ackdat': 0.0, 'is_sm_ips_ports': 0, 'ct_state_ttl': 0, 'ct_flw_http_mthd': 0,
        'is_ftp_login': 0, 'ct_ftp_cmd': 0, 'ct_srv_src': 0, 'ct_srv_dst': 0, 'ct_dst_ltm': 0,
        'ct_src_ltm': 0, 'ct_src_dport_ltm': 0, 'ct_dst_sport_ltm': 0, 'ct_dst_src_ltm': 0
    }

    if not packet.haslayer("IP"):
        print("Skipping non-IP packet")
        return None, "Anomaly Detected: Non-IP packet"

    src_ip = packet["IP"].src
    dst_ip = packet["IP"].dst
    sport = packet["TCP"].sport if packet.haslayer("TCP") else packet["UDP"].sport if packet.haslayer("UDP") else 0
    dport = packet["TCP"].dport if packet.haslayer("TCP") else packet["UDP"].dport if packet.haslayer("UDP") else 0
    flow_key = (src_ip, dst_ip, sport, dport)
    
    flow = flow_data[flow_key]
    flow['packets'] += 1
    flow['bytes'] += len(packet)
    if flow['start_time'] == 0:
        flow['start_time'] = time.time()
    duration = time.time() - flow['start_time']
    if duration < 0.001:  # Prevent division by zero or infinite Sload
        duration = 0.001
    
    features['dur'] = duration
    features['Spkts'] = flow['packets']
    features['Dpkts'] = 0
    features['Sload'] = (flow['bytes'] * 8 / duration) if duration > 0 else 0
    features['Dload'] = 0
    features['ct_srv_src'] = len([k for k in flow_data if k[0] == src_ip])
    features['ct_dst_sport_ltm'] = len([k for k in flow_data if k[1] == dst_ip and k[3] != dport])
    
    if packet.haslayer("TCP"):
        features['proto'] = 'tcp'
        if packet["TCP"].flags & 0x02:  # SYN
            features['state'] = 'INT'
        elif packet["TCP"].flags & 0x01:  # FIN
            features['state'] = 'FIN'
        elif packet["TCP"].flags & 0x04:  # RST
            features['state'] = 'RST'
        elif packet["TCP"].flags & 0x10:  # ACK
            features['state'] = 'CON'
        features['swin'] = packet["TCP"].window
        features['dwin'] = 0
    elif packet.haslayer("UDP"):
        features['proto'] = 'udp'
        features['state'] = 'INT'
    elif packet.haslayer("ICMP"):
        features['proto'] = 'icmp'
        features['state'] = 'INT'
    else:
        print("Unsupported protocol, defaulting to 'tcp'")
        features['proto'] = 'tcp'

    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        if dport == 80:
            features['service'] = 'http'
        elif dport == 21:
            features['service'] = 'ftp'
        elif dport == 53:
            features['service'] = 'dns'

    current_time = time.time()
    features['Stime'] = current_time
    features['Ltime'] = current_time

    length = len(packet)
    features['sbytes'] = length
    features['dbytes'] = 0
    features['smeansz'] = length
    features['dmeansz'] = 0

    features['sttl'] = packet["IP"].ttl
    features['dttl'] = 0

    features['stcpb'] = 0
    features['dtcpb'] = 0
    features['trans_depth'] = 0
    features['res_bdy_len'] = 0
    features['Sjit'] = 0.0
    features['Djit'] = 0.0
    features['Sintpkt'] = 0.0
    features['Dintpkt'] = 0.0
    features['tcprtt'] = 0.0
    features['synack'] = 0.0
    features['ackdat'] = 0.0
    features['is_sm_ips_ports'] = 0
    features['ct_state_ttl'] = 0
    features['ct_flw_http_mthd'] = 0
    features['is_ftp_login'] = 0
    features['ct_ftp_cmd'] = 0
    features['ct_srv_dst'] = 0
    features['ct_dst_ltm'] = 0
    features['ct_src_ltm'] = 0
    features['ct_src_dport_ltm'] = 0
    features['ct_dst_sport_ltm'] = min(features['ct_dst_sport_ltm'], 10)  # Cap to training range

    # Convert to DataFrame
    df = pd.DataFrame([features])

    # Ensure all expected columns are present
    expected_columns = cat_col + num_col
    missing_columns = [col for col in expected_columns if col not in df.columns]
    if missing_columns:
        print(f"Missing columns in DataFrame: {missing_columns}")
        for col in missing_columns:
            df[col] = 0

    # Reorder columns to match training data
    df = df[expected_columns]

    # Debug: Print features and columns
    print(f"Extracted features: {features}")
    print(f"Columns before scaling: {df[num_col].columns.tolist()}")

    # Scale numerical columns
    try:
        df[num_col] = scaler.transform(df[num_col])
    except Exception as e:
        print(f"Error in StandardScaler: {e}")
        return None, f"Anomaly Detected: StandardScaler error - {str(e)}"

    # Apply ColumnTransformer
    try:
        transformed = ct.transform(df)
        if transformed.shape[1] != 204:
            print(f"Feature mismatch: Expected 204 features, got {transformed.shape[1]}")
            return None, f"Anomaly Detected: Feature mismatch - expected 204, got {transformed.shape[1]}"
        features_array = transformed.reshape(1, 204)
        print(f"Transformed features shape: {features_array.shape}")
        return features_array, None
    except Exception as e:
        print(f"Error in ColumnTransformer: {e}")
        return None, f"Anomaly Detected: ColumnTransformer error - {str(e)}"

# Handle captured packets
def packet_handler(packet):
    packet_queue.put(packet)

# Function to capture packets continuously
def capture_traffic():
    iface = "\\Device\\NPF_Loopback"  # Adjust interface as needed
    print(f"Capturing traffic on interface: {iface}")
    sniff(iface=iface, prn=packet_handler, store=False)

# Process packets and emit detections
def process_packets():
    while True:
        try:
            packet = packet_queue.get(timeout=1)
            ip_address = packet.getlayer("IP").src if packet.haslayer("IP") else "Unknown"
            features_array, error_msg = extract_features(packet)
            
            detection = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip_address": ip_address,
                "predicted_class": -1,  # Use -1 for anomalies
                "attack_type": "Anomaly Detected",
                "confidence": 1.0
            }

            if error_msg:
                # Handle anomaly detection
                with detections_lock:
                    detections.append(detection)
                    if len(detections) > 100:
                        detections.pop(0)
                socketio.emit('new_detection', detection)
                print(f"Detected: {error_msg} from {ip_address}")
                logging.info(f"Detected: {error_msg} from {ip_address}")
                continue

            if features_array is not None:
                try:
                    pred_prob = model.predict(features_array, verbose=0)
                    predicted_class = np.argmax(pred_prob, axis=1)[0]
                    confidence = pred_prob[0][predicted_class]

                    detection = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip_address": ip_address,
                        "predicted_class": int(predicted_class),
                        "attack_type": attack_types[predicted_class],
                        "confidence": float(confidence)
                    }

                    with detections_lock:
                        detections.append(detection)
                        if len(detections) > 100:
                            detections.pop(0)

                    socketio.emit('new_detection', detection)
                    print(f"IP: {ip_address}, Predicted: {attack_types[predicted_class]}, Confidence: {confidence:.2f}, Probabilities: {pred_prob[0]}")
                    print(f"Key features: Spkts={features_array['Spkts'] if 'Spkts' in features_array else 'N/A'}, Sload={features_array['Sload'] if 'Sload' in features_array else 'N/A'}, ct_srv_src={features_array['ct_srv_src'] if 'ct_srv_src' in features_array else 'N/A'}, ct_dst_sport_ltm={features_array['ct_dst_sport_ltm'] if 'ct_dst_sport_ltm' in features_array else 'N/A'}")
                    logging.info(f"Detected: {attack_types[predicted_class]} from {ip_address} with confidence {confidence:.2f}")
                except Exception as e:
                    detection["attack_type"] = "Anomaly Detected"
                    detection["confidence"] = 1.0
                    with detections_lock:
                        detections.append(detection)
                        if len(detections) > 100:
                            detections.pop(0)
                    socketio.emit('new_detection', detection)
                    print(f"Error during prediction: {e}")
                    logging.error(f"Error during prediction: {e}")
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error in processing packets: {e}")
            logging.error(f"Error in processing packets: {e}")

# Serve index.html at the root
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

# Serve other static files (if needed by index.html)
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# Flask API to serve initial detections
@app.route('/api/detections', methods=['GET'])
def get_detections():
    with detections_lock:
        return jsonify(detections)

# Run the traffic capture in a separate thread
def start_traffic_capture():
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.daemon = True
    capture_thread.start()

# Run the traffic processing in a separate thread
def start_traffic_processing():
    process_thread = threading.Thread(target=process_packets)
    process_thread.daemon = True
    process_thread.start()

# Honeypot simulation
def honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(5)
    print("Honeypot listening on port 8080...")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            logging.info(f"Connection from {addr}")
            client_socket.send(b"Welcome to the honeypot!\n")
            client_socket.close()
        except Exception as e:
            print(f"Error in honeypot loop: {e}")
            logging.error(f"Error in honeypot loop: {e}")
            client_socket.close()

if __name__ == "__main__":
    start_traffic_capture()
    start_traffic_processing()
    
    honeypot_thread = threading.Thread(target=honeypot)
    honeypot_thread.daemon = True
    honeypot_thread.start()

    socketio.run(app, host='localhost', port=5000, debug=True)
