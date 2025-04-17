# TheListener 👂
---

**A powerful man-in-the-middle (MITM) attack automation suite designed for red teamers and penetration testers.**
This tool leverages `Bettercap`, `Nmap`, and `Scapy` to monitor, fingerprint, and intercept traffic across a local network in real time with a live dashboard, URL/credential logging, OS detection, and optional full-target mode.

> 🔧 Includes a one-command install script to set up dependencies and ensure full compatibility on any modern Linux distribution (Kali, Parrot, Ubuntu, etc).
> 📃 Includes a log reader for easy viewing

---

## 🚀 Features

- 📡 Auto interface and network detection
- 🧭 Live host discovery (no timeout)
- 🕵️ Real-time OS detection (active + passive TTL)
- 📊 Live traffic dashboard (Airodump-ng style)
- 🔓 Credentials and URLs extracted from intercepted HTTP/S
- 🎯 Target a specific device or MITM the entire network
- 🧾 Timestamped logs saved per session
- 🧠 Automatically filters out known tracking/ad domains in the logs
- 📁 Built-in Flask log reader with search, graphs, and credential filters

---

## 📦 Installation

1. **Clone the repository**:

```bash
git clone https://github.com/BlackPaw21/TheListener.git
cd TheListener
```

2. **Run the installer script** (will update your system and install required packages):

```bash
chmod +x update.sh
./update.sh
```

> ✅ The script installs: `nmap`, `bettercap`, `scapy`, `lxml`, `flask`, `python3-pip`, and system libraries like `net-tools`, `libpcap-dev`, etc.

---

## 🧪 Usage

```bash
sudo python3 TheListener.py
```

- Select a network interface by index
- Press `s` to stop traffic monitoring and pick a target
- Choose single target spoofing or `a` for full network MITM
- Live logs are saved to `/logs` with timestamped filenames

---

## 🌐 Web Log Viewer

After running EvenBetterCap and capturing data, you can view and analyze logs with a GUI:

```bash
python3 reader.py
```

Open your browser and go to:  
📍 `http://localhost:5000`

### Tabs:
- **All Logs** — searchable real-time log viewer  
- **Top Visited URLs** — bar chart of the most requested domains (ads filtered out)  
- **Detected Credentials** — shows only potential login/authorization hits  

---


## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing** only.  
Using EvenBetterCap on networks you do not own or have permission to audit is **illegal**.
