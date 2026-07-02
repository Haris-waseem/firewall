# Terminal — Packet Filtering Firewall Simulator

A fully functional, GUI-based **packet filtering firewall simulator** built from scratch in C++17. Simulates real-world firewall behavior including multi-stage packet inspection, real-time threat detection, an interactive admin CLI, and a dual persistence layer — all visualized through a live Dear ImGui dashboard.

> Built as a major systems project at COMSATS University Islamabad, demonstrating applied data structures, network security concepts, and C++ systems programming.

---

## 📸 Screenshots

> <img width="1919" height="700" alt="image" src="https://github.com/user-attachments/assets/f02024a7-1a88-4c5c-884a-2ea73e9ab8d1" />

---

## ✨ Key Features

- **Real-time GUI Dashboard** — 7 dedicated panels built with Dear ImGui and ImPlot: Dashboard, Rules, Blacklist, Traffic, Threats, Logs, and Settings
- **Multi-stage Packet Inspection Pipeline** — whitelist/blacklist O(1) hash lookups → BST O(log n) rule matching → configurable default policy fallback
- **Real-time Threat Detection** — sliding time-window algorithms detect SYN flood attacks and port scanning activity automatically
- **Admin REPL CLI** — interactive `firewall>` shell with 20+ commands for live rule management, IP control, packet injection, and log querying
- **Dual Persistence Layer** — MongoDB C++ driver (mongocxx/bsoncxx) with automatic fallback to flat-file CSV logging when MongoDB is unavailable
- **5 Custom Data Structures** — LinkedList, BST, HashMap, Stack, Queue implemented from scratch with no STL container substitutions

---

## 🏗️ Project Structure

```
Terminal/
├── src/                    # Core backend logic
│   ├── main.cpp
│   ├── RuleEngine.cpp      # Multi-stage packet evaluation pipeline
│   ├── TrafficMonitor.cpp  # SYN flood & port scan detection
│   ├── AdminCLI.cpp        # Interactive REPL shell
│   ├── PacketProcessor.cpp
│   ├── PacketSimulator.cpp
│   ├── MongoLogger.cpp     # MongoDB persistence layer
│   ├── FileLogger.cpp      # Flat-file CSV fallback logger
│   └── ...                 # LinkedList, BST, HashMap, Stack, Queue
├── include/                # Header files
├── gui/                    # Dear ImGui GUI layer
│   ├── FirewallGUI.cpp
│   ├── TerminalPanel.cpp
│   └── panels/             # Dashboard, Rules, Blacklist, Traffic, Threats, Logs, Settings
├── third_party/            # Vendored ImGui 1.92.8 and ImPlot 1.0
├── fonts/                  # UI fonts (Inter, JetBrains Mono, Font Awesome)
├── rules.conf              # Firewall rules configuration file
├── CMakeLists.txt
└── build.bat               # Windows one-click build script (MSVC)
```

---

## 🔍 Packet Inspection Pipeline

```
[ Incoming Packet ]
       │
       ▼
 1. Validation ───────────► (Invalid?) ──────────► [ BLOCK — Code -4 ]
       │
       ▼
 2. Queue Buffer ──────────► (Overflow?) ─────────► [ BLOCK — Code -5 ]
       │
       ▼
 3. Threat Monitor ────────► (SYN Flood / Port Scan?) ─► [ Blacklist IP & Alert ]
       │
       ▼
 4. O(1) Whitelist ────────► (Whitelisted?) ──────► [ ALLOW — Code -1 ]
       │
       ▼
 5. O(1) Blacklist ────────► (Blacklisted?) ──────► [ BLOCK — Code -2 ]
       │
       ▼
 6. O(log n) BST Match ────► (Rule matched?) ─────► [ Rule Action Decision ]
       │                                                      │
       ▼ (No match)                                           ▼
 7. Default Policy ───────────────────────────────► [ ALLOW / BLOCK ]
       │
       ▼
 [ Log to CSV / MongoDB ] ──► [ Push to History Stack ]
```

---

## 📊 Custom Data Structures

| Structure | Purpose | Key Complexity |
|-----------|---------|----------------|
| **LinkedList** | Stores active rules in sorted order; used for config save/load | Insert O(n), Lookup O(n) |
| **BST** | Priority-indexed rule matching during packet evaluation | Match O(log n) avg |
| **HashMap** | Whitelist/blacklist O(1) IP lookups; sliding window threat counters (djb2 hash, separate chaining, rehash at 0.75 load) | Lookup O(1) |
| **Stack** | Circular LIFO history buffer (capacity 100, overwrites oldest on full) | Push/Pop O(1) |
| **Queue** | Circular FIFO packet ingestion buffer with overflow tracking | Enqueue/Dequeue O(1) |

---

## 🛠️ Build & Run

### Requirements

| Dependency | Required | Notes |
|-----------|----------|-------|
| C++17 compiler (MSVC / GCC / Clang) | ✅ Yes | |
| CMake 3.15+ | ✅ Yes | |
| OpenGL | ✅ Yes | Comes with GPU drivers — no separate install |
| GLFW3 | ✅ Yes | Bundled in `third_party/` — no separate install needed for MSVC |
| Dear ImGui + ImPlot | ✅ Yes | Vendored in `third_party/` — compiled automatically |
| MongoDB + mongocxx drivers | ⚙️ Optional | Only needed if building with `-DWITH_MONGODB=ON`; app falls back to CSV otherwise |

### Option A: Windows One-Click (MSVC)

Requires Visual Studio Build Tools installed.

```bat
build.bat
```

### Option B: CMake (Cross-platform)

```bash
mkdir build && cd build

# Default build (flat-file CSV persistence)
cmake ..
cmake --build . --config Release

# Optional: enable MongoDB persistence
cmake -DWITH_MONGODB=ON ..
cmake --build . --config Release
```

### Option C: Direct GCC (no CMake)

```bash
g++ -std=c++17 src/*.cpp -Iinclude -o Firewall.exe
./Firewall.exe
```

---

## ▶️ Running

### GUI Mode (Default)
```bash
./Firewall
```
Launches the full Dear ImGui dashboard with all 7 panels (Dashboard, Rules, Blacklist, Traffic, Threats, Logs, Settings).

### CLI Mode
```bash
./Firewall --cli
```
Launches the interactive `firewall>` REPL shell only, with no GUI window.

> **Note:** If the GUI fails to initialize (e.g. missing OpenGL context), the app automatically falls back to CLI mode so it's never left without a usable interface.

---

## 🎮 Admin CLI — Command Reference

Available in CLI mode (`--cli`) or via the Terminal panel inside the GUI:

### Rule Management
```
add-rule <action> <dir> <proto> <ip> <port> [priority] [desc]
del-rule <ruleID>
update-rule <ruleID> <ALLOW|BLOCK|LOG_ONLY>
enable-rule <ruleID> / disable-rule <ruleID>
list-rules
flush-rules
```

### IP Control
```
block-ip <ip>        # O(1) blacklist
allow-ip <ip>        # O(1) whitelist
remove-block <ip>    # Remove from blacklist
remove-allow <ip>    # Remove from whitelist
set-policy <ALLOW|BLOCK>
```

### Monitoring & Simulation
```
show-stats
show-history [n]
send-packet <srcIP> <destPort> <proto> [dir] [isSYN]
set-threshold <syn|portscan|window> <value>
reset-threats
```

### Persistence & Queries
```
query --ip <ip>
query --action <ALLOW|BLOCK>
query --last <minutes>
save / load
exit
```

---

## 🗄️ Persistence Format

**`rules.conf`**
```ini
[RULES]
001 010 ALLOW BOTH ANY 192.168.1.100 -1 Whitelist Admin Machine
002 100 BLOCK BOTH ANY * 23 Block Telnet Port
DEFAULT_POLICY BLOCK

[BLACKLIST]
192.168.1.99

[WHITELIST]
10.0.0.5
```

**`firewall.log`** (CSV)
```
2026-05-31T13:09:20Z,1,192.168.1.100,10.0.0.1,80,TCP,INBOUND,ALLOW,-1,NONE
2026-05-31T13:09:30Z,-1,10.0.0.99,*,0,TCP,INBOUND,BLOCK,-2,SYN_FLOOD
```

---

## 📄 License

This project is for educational and portfolio purposes.
