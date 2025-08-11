Network Intrusion Detection //

This repository contains a Python-based Detector server (Detector.py) designed to monitor network traffic, detect intrusions using a pre-trained Keras deep learning model, and display real-time detections on a web dashboard. The system captures network packets using Scapy, processes them to extract features, predicts attack types (e.g., normal, exploits, DoS) using a neural network, and logs connections to a simulated Detector service. The dashboard, powered by Flask and SocketIO, shows the latest detections and updates in real-time via WebSockets.
Features

Real-Time Packet Capture: Uses Scapy to capture network packets on a specified interface.
Intrusion Detection: Extracts features from packets and classifies them using a pre-trained Keras model, supporting 10 attack types (e.g., normal, generic, fuzzers, exploits, DoS).
Attack Simulation: Listens on port 8080 for unauthorized connections, logging them as anomalies.
Web Dashboard: Displays the latest 100 detections with IP addresses, timestamps, predicted attack types, and confidence scores, updated in real-time via WebSocket.
Logging: Saves detections to detections.log for analysis.
Feature Preprocessing: Uses a pre-trained ColumnTransformer and StandardScaler for consistent feature processing.

Prerequisites

Python 3.x
Npcap: Required for Scapy on Windows. Download from https://nmap.org/npcap/ and install with WinPcap compatibility.
Network Interface: A valid network interface 
Administrator Privileges: Required for packet capture on Windows.

Installation

Clone the Repository:
git clone <repository-url>
cd <repository-name>


Install Dependencies:Install the required Python packages using pip:
pip install flask flask-socketio scapy numpy pandas tensorflow joblib


Install Npcap:

Download and install Npcap from https://nmap.org/npcap/.
Ensure WinPcap compatibility is enabled during installation.


Verify Files:Ensure the following files are in the repository root:

Detector.py: Main server script.
my_model.h5: Pre-trained Keras model.
column_transformer.pkl: Preprocessing pipeline for categorical features.
scaler.pkl: Preprocessing pipeline for numerical features.
num_col.pkl: List of numerical columns.
index.html: Web dashboard interface.



Usage

Update Network Interface:

The default interface is set to \Device\NPF_Loopback. Update the iface variable in the capture_traffic function to match your network interface (e.g., \Device\NPF_{XXXXXXXx-XXXXX-XXXXXX_XXX} for Wi-Fi with IP 172.18.32.99).
To find your interface, run:from scapy.all import *
for iface in get_if_list():
    try:
        print(f"Interface: {iface}, Address: {get_if_addr(iface)}")
    except:
        print(f"Interface: {iface}, Address: Unknown")




Run the Server:

Open a Command Prompt or PowerShell as Administrator.
Navigate to the repository directory:cd path/to/repository


Run the script:python Detector.py


Expected output:Model loaded successfully
Preprocessing pipeline and columns loaded successfully
Loaded num_col: [...]
Capturing traffic on interface: any interface (change accordingly)
Honeypot listening on port 8080...
* Running on http://localhost:5000




Access the Dashboard:

Open a browser and navigate to http://localhost:5000.
The dashboard displays up to 100 recent detections, including:
Timestamp
Source IP address
Predicted attack type (e.g., normal, exploits, DoS)
Confidence score


Detections update in real-time via WebSocket.


Simulate an Attack:

To test intrusion detection, run a port scan against Detectors’s IP (e.g., 172.18.32.99):from scapy.all import *
import random

target_ip = "172.18.32.99"
ports = range(1, 100)
packets = []
for port in ports:
    ip = IP(dst=target_ip)
    tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    pkt = ip/tcp
    packets.append(pkt)
send(packets, loop=0, inter=0.01)


Run as Administrator: python port_scan.py.
Check the console and dashboard for detections, e.g.:Detected: Reconaissance from 172.18.32.X with confidence 0.95




View Logs:

Detections are logged to detections.log in the repository root.
Example log entry:2025-05-04 18:31:00,000 - Detected: Exploits from 172.18.32.X with confidence 0.92





Project Structure
<repository-name>/
│
├── Detector.py         # Main server script
├── my_model.h5                # Pre-trained Keras model
├── column_transformer.pkl     # Preprocessing pipeline for categorical features
├── scaler.pkl                 # Preprocessing pipeline for numerical features
├── num_col.pkl                # List of numerical columns
├── index.html                 # Web dashboard interface
├── detections.log             # Log file for detections

Troubleshooting

No Detections in Dashboard:

Ensure the correct network interface is set in capture_traffic.
Verify WebSocket connection: Check browser console for errors.
Confirm index.html is in the repository root.


Model or Preprocessing Errors:

Check console for errors like Error loading model or Error in ColumnTransformer.
Ensure my_model.h5, column_transformer.pkl, scaler.pkl, and num_col.pkl are present and compatible with your TensorFlow version.


Scapy Issues:

If you see Layer [IP] not found or Failed to start Scapy, confirm Npcap is installed.
Run as Administrator: net session should not error.
Verify the interface with the Scapy interface check script (see Usage step 1).


Honeypot Not Detecting Connections:

Ensure port 8080 is open: netstat -an | findstr 8080.
Test with telnet localhost 8080 from another terminal.


Feature Mismatch Errors:

If Feature mismatch: Expected 204 features, got X, verify the num_col and cat_col match the training data.
Check console output for missing columns in extract_features.



Notes

Network Interface: The default interface is \Device\NPF_Loopback, which may not capture external traffic. Update to your Wi-Fi interface (e.g., \Device\NPF_{8852DE73-62AC-4CCC-9780-975BD8AD3673}) for real-world use.
Attack Types: The model classifies packets into 10 classes: normal, generic, fuzzers, exploits, DoS, reconaissance, backdoor, analysis, shellcode, worms.
Performance: The system limits in-memory detections to 100 to optimize performance.
Security: This is a demo honeypot. For production, secure Flask and SocketIO (e.g., use HTTPS, authentication).

Contributing
Contributions are welcome! Please submit a pull request or open an issue for bug reports or feature requests.
License
This project is licensed under the MIT License.
