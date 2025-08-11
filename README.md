# 🛡️ AI Attack Detector

A **Python-based Network Attack Detector Server** that captures network packets in real-time, detects intrusions using a **pre-trained Keras Deep Learning Model**, and displays detections on a **real-time web dashboard**.

---

## 🚀 **Features**
- **📡 Real-Time Packet Capture** — Uses **Scapy** to capture network packets.
- **🧠 Intrusion Detection** — Classifies packets into **10 attack categories**:
  - `normal`, `generic`, `fuzzers`, `exploits`, `DoS`, `reconnaissance`, `backdoor`, `analysis`, `shellcode`, `worms`.
- **🎯 Detector Simulation** — Listens on **port 8080** for unauthorized connections.
- **📊 Web Dashboard** — Live updates with:
  - Timestamp  
  - Source IP Address  
  - Predicted Attack Type  
  - Confidence Score  
- **📝 Logging** — Saves all detections to `detections.log` for later analysis.
- **⚡ Preprocessing** — Uses a **pre-trained ColumnTransformer** & **StandardScaler** for consistent feature extraction.

---

## 📋 **Prerequisites**
- **Python 3.x**
- **Npcap** (for Scapy on Windows) — [Download here](https://nmap.org/npcap/) (enable **WinPcap compatibility** during install).
- **Administrator Privileges** (for packet capture on Windows).

---

## ⚙️ **Installation**
```bash
# Clone the repository
git clone <repository-url>
cd <repository-name>

# Install dependencies
pip install flask flask-socketio scapy numpy pandas tensorflow joblib

````

**Install Npcap**:

* Download & install from [Npcap official site](https://nmap.org/npcap/).
* Ensure **WinPcap compatibility** is checked.

---

## 🖥️ **Usage**

### **1️⃣ Set Network Interface**

In `detector_server5.py` (or your file), update:

```python
iface = r"\Device\NPF_Loopback"
```

to match your **Wi-Fi/Ethernet adapter**.
To list available interfaces:

```python
from scapy.all import *
for iface in get_if_list():
    try:
        print(f"Interface: {iface}, Address: {get_if_addr(iface)}")
    except:
        print(f"Interface: {iface}, Address: Unknown")
```

---

### **2️⃣ Run the Server**

```bash
python detector_server5.py
```

Expected Output:

```
Model loaded successfully
Preprocessing pipeline loaded successfully
Capturing traffic on interface: \Device\NPF_{xxxx}
Detector listening on port 8080...
* Running on http://localhost:5000
```

---

### **3️⃣ Access the Dashboard**

Open your browser and go to:

```
http://localhost:5000
```

You will see:

* Timestamp
* Source IP
* Predicted Attack Type
* Confidence Score
  *(Updated in real-time via WebSocket)*

---

### **4️⃣ Simulate an Attack**

Example: Port scan using Scapy

```python
from scapy.all import *
import random

target_ip = "172.18.32.99"
ports = range(1, 100)
packets = []

for port in ports:
    ip = IP(dst=target_ip)
    tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    packets.append(ip/tcp)

send(packets, inter=0.01)
```

---

## 📂 **Project Structure**

```
<repository-name>/
│── detector_server5.py       # Main server script
│── my_model.h5               # Pre-trained Keras model
│── column_transformer.pkl    # Preprocessing pipeline for categorical features
│── scaler.pkl                # Preprocessing pipeline for numerical features
│── num_col.pkl               # List of numerical columns
│── index.html                # Web dashboard interface
│── detections.log            # Log file for detections
```

---

## 🛠️ **Troubleshooting**

* **No detections** → Check network interface in `detector_server5.py`.
* **Model errors** → Ensure `.h5` and `.pkl` files match training environment.
* **Scapy issues** → Run script as **Administrator** & verify Npcap installation.
* **Port 8080 issues** → Ensure it’s open using:

  ```bash
  netstat -an | findstr 8080
  ```

---

## 📌 **Notes**

* Default interface is **Loopback** — change it for real-world monitoring.
* Limited to **latest 100 detections** in dashboard for performance.
* This is a **demo detector** — secure Flask & SocketIO in production.

---



