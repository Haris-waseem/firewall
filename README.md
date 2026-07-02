# C++ Packet Filtering Firewall — DSA Major Project

An advanced, production-grade command-line **Packet Filtering Firewall and Traffic Monitor** built entirely from scratch in C++. 

This project simulates network packet inspection using **5 custom data structures** (implemented without using STL container classes like `std::list`, `std::map`, `std::stack`, or `std::queue` for core operations), detects anomaly threats in real-time (SYN flooding and port scanning), and persists firewall logs/rules utilizing flat-file CSV and a gracefully-degrading **MongoDB backend**.

---

## 🚀 Key Features

*   **Custom Data Structures (No STL)**: Handcrafted memory-efficient implementations of **LinkedList**, **Binary Search Tree (BST)**, **HashMap**, **Stack**, and **Queue**.
*   **Dual Matching Engine**:
    *   **O(1) Fast Checks**: Whitelist and Blacklist IP tables powered by custom HashMaps.
    *   **O(log n) Rule Matching**: Binary Search Tree indexed by rule priority (lower priority number = higher precedence) to find the highest-priority rule match efficiently.
*   **Real-time Threat Monitoring**:
    *   **SYN Flood Detection**: Tracks TCP SYN packets from a source IP in a sliding time-window to detect and block denial-of-service attempts.
    *   **Port Scan Detection**: Detects horizontal scanning by counting distinct target ports probed by a single source IP in a sliding time-window.
*   **Polished Admin CLI REPL**: An interactive command-line interface shell with a gorgeous command dashboard, rule editor, stat inspector, packet injector, and historical query system.
*   **Dual Persistence Layer**:
    *   **Flat-file Logger**: Appends CSV log entries and saves rule sets to a structured `rules.conf` configuration file.
    *   **MongoDB Connector**: Upserts records and logs to MongoDB. Gracefully degrades to stub operations without compile-time errors if MongoDB drivers are missing.

---

## 🏛️ Project Architecture & Data Flow

The firewall is designed around a decoupled Model-View-Controller (MVC) architecture:
*   **Model**: Core data structures, `Packet`, `Rule`, `RuleNode`, and `FirewallStats`.
*   **View**: Formatted output screens, stat summaries, and logs.
*   **Controller**: `AdminCLI`, which handles parsing, command routing, and input validation.

### Packet Inspection Pipeline Sequence

```
[ Incoming Packet ]
       │
       ▼
 1. Validation ───────► (Invalid Format?) ───────► [ BLOCK & Log Code -4 ]
       │
       ▼
 2. Queue Buffer ─────► (Queue Full Overflow?) ──► [ BLOCK & Log Code -5 ]
       │
       ▼
 3. Threat Monitor ───► (SYN Flood / Port Scan?) ──► [ Blacklist IP & Alert ]
       │
       ▼
 4. O(1) Whitelist ───► (Whitelisted Source IP?) ──► [ ALLOW & Log Code -1 ]
       │
       ▼
 5. O(1) Blacklist ───► (Blacklisted Source IP?) ──► [ BLOCK & Log Code -2 ]
       │
       ▼
 6. O(log n) BST Match ─► (Found Matching Rule?) ───► [ Rule Action Decision ]
       │                                                      │
       ▼ (No Match)                                           ▼
 7. Default Policy ──────────────────────────────────► [ BLOCK / ALLOW ]
       │
       ▼
 [ Log CSV & MongoDB ] ───► [ Push to LIFO History Stack ]
```

---

## 📊 Detail Analysis of Custom Data Structures

### 1. Singly-Linked List (`LinkedList.h`)
*   **Purpose**: Manages active rules in insertion/ID sorted order. Used to save config sets, display rule tables sequentially, and load items in bulk.
*   **Complexity**:
    *   **Sorted Insertion (`insertSorted`)**: $O(n)$ linear scan to maintain ascending priority sequence.
    *   **Removal (`remove`)**: $O(n)$ search and pointer rewrite.
    *   **Lookup (`find`)**: $O(n)$ sequential search.
*   **Memory Management**: Deconstructs dynamically. Loops through nodes deleting `RuleNode` memory to prevent leaks.

### 2. Binary Search Tree (`BST.h`)
*   **Purpose**: Stores rules keyed on `Rule::priority`. Performs O(log n) packet evaluations.
*   **Algorithm (`findBestMatch`)**: Traverses in-order (left-root-right) looking for rules matching the incoming packet. Because left subtrees contain lower priority numbers (higher precedence), the first match encountered is guaranteed to be the highest-precedence rule.
*   **Complexity**:
    *   **Insertion (`insert`)**: $O(\log n)$ average | $O(n)$ degenerate (unbalanced skewed line).
    *   **Match Evaluation**: $O(\log n)$ average | $O(n)$ worst.

### 3. Hash Map (`HashMap.h`)
*   **Purpose**: Handles O(1) IP address whitelist/blacklist matches and sliding window SYN/port-scan counters.
*   **Design**:
    *   **Hash Function**: Dan Bernstein's `djb2` string hash algorithm (constant multiplier 33 and initial hash 5381), which yields an exceptionally uniform distribution for IP address strings.
    *   **Collision Resolution**: Separate Chaining using `std::list` buckets.
    *   **Dynamic Rehash**: Automatically doubles the bucket count and re-inserts all keys when the load factor exceeds `0.75` to keep lookups at $O(1)$.

### 4. Stack (`Stack.h`)
*   **Purpose**: Sliding log history archiving (Last-In-First-Out).
*   **Design**: A fixed-capacity circular array index buffer of size `100`. When a push operation occurs on a full stack, it loops back and overwrites the oldest element without shifting memory (O(1)).
*   **Complexity**:
    *   **Push / Pop / Peek**: $O(1)$ constant time.
    *   **Display (`printTop`)**: $O(n)$ loop using modular index step-back math: `idx = (top - i + capacity) % capacity`.

### 5. Queue (`Queue.h`)
*   **Purpose**: Processing buffer for network packet ingestion (First-In-First-Out).
*   **Design**: A fixed-capacity circular array using `front_`, `rear_`, and `count_` index pointers.
*   **Complexity**:
    *   **Enqueue / Dequeue**: $O(1)$ operations.
    *   **Safety**: Tracks overflows via an internal counter if incoming packet spikes exceed capacity.

---

## 🛠️ Compilation & Execution Guide

The project is fully compatible with any modern C++17 compiler (GCC, Clang, or MSVC) and is configured to compile out-of-the-box using **CMake**.

### Option A: Building with CMake (Recommended)

1.  Open your terminal in the project directory.
2.  Create a build directory:
    ```powershell
    mkdir build
    cd build
    ```
3.  Configure with CMake:
    *   **Flat-file csv persistence mode (Default)**:
        ```powershell
        cmake ..
        ```
    *   **MongoDB database integration mode** (requires `mongocxx` installed):
        ```powershell
        cmake -DWITH_MONGODB=ON ..
        ```
4.  Compile the source:
    ```powershell
    cmake --build . --config Release
    ```
5.  Run the executable:
    ```powershell
    ./Firewall
    ```

### Option B: Compiling Directly with GCC/G++

If you do not have CMake, you can compile all source files directly using standard G++:
```powershell
g++ -std=c++17 src/*.cpp -Iinclude -o Firewall.exe
./Firewall.exe
```

---

## 🎮 Admin CLI Commands Reference

Once running, the interactive prompt `firewall> ` will accept administrative operations:

### 1. Rule Management
*   `add-rule <action> <dir> <proto> <ip> <port> [priority] [desc]`
    *   **Example**: `add-rule BLOCK INBOUND TCP 192.168.1.150 22 10 Block SSH connection`
*   `del-rule <ruleID>`
    *   **Example**: `del-rule 3`
*   `update-rule <ruleID> <ALLOW|BLOCK|LOG_ONLY>`
    *   **Example**: `update-rule 1 ALLOW`
*   `enable-rule <ruleID>` / `disable-rule <ruleID>`
*   `list-rules` (Prints a beautiful formatted rules table)
*   `flush-rules` (Cleans ruleset, whitelist, and blacklist completely)

### 2. IP Whitelists & Blacklists
*   `block-ip <ip>`: Explicitly blacklists an IP address (O(1) block).
*   `allow-ip <ip>`: Explicitly whitelists an IP address (O(1) pass).
*   `remove-block <ip>` / `remove-allow <ip>`
*   `set-policy <ALLOW|BLOCK>`: Changes default policy action when no rules match.

### 3. Monitoring & Simulation
*   `show-stats`: Displays a clean, double-lined boxed summary of processed, blocked, logged, and overflow packet counters.
*   `show-history [n]`: Shows the last $N$ packets popped from the circular stack history.
*   `send-packet <srcIP> <destPort> <proto> [dir] [isSYN]`
    *   *Inject a normal packet*: `send-packet 192.168.1.50 80 TCP`
    *   *Simulate SYN flood attack*: Inject multiple SYN packets rapidly: `send-packet 10.0.0.99 443 TCP INBOUND SYN`
*   `set-threshold <syn|portscan|window> <value>`: Sets threat metrics.
*   `reset-threats`: Resets current sliding threat window.

### 4. Persistence & Log Queries
*   `query --ip <ip>`: Performs log search for a specific source IP.
*   `query --action <ALLOW|BLOCK>`: Searches logs based on decision.
*   `query --last <minutes>`: Displays log lines logged in the past $N$ minutes.
*   `save`: Forces manual config commit to `rules.conf`.
*   `load`: Reloads rule, whitelist, blacklist tables from `rules.conf`.
*   `exit`: Commits active firewall configuration and closes REPL.

---

## 🗄️ Persistence File Layout

### Configuration File (`rules.conf`)
Rules are saved under distinct brackets in a structured format:
```ini
# Rules Configuration File
# Automatically generated by Firewall System

[RULES]
001 010 ALLOW BOTH ANY 192.168.1.100 -1 Whitelist Admin Machine
002 100 BLOCK BOTH ANY * 23 Block Telnet Port
DEFAULT_POLICY BLOCK

[BLACKLIST]
192.168.1.99
192.168.1.200

[WHITELIST]
10.0.0.5
```

### Log File (`firewall.log`)
Appends events in standard 10-field CSV logs for parsing and queries:
```csv
2026-05-31T13:09:20Z,1,192.168.1.100,10.0.0.1,80,TCP,INBOUND,ALLOW,-1,NONE
2026-05-31T13:09:25Z,2,192.168.1.99,10.0.0.1,23,TCP,INBOUND,BLOCK,-2,NONE
2026-05-31T13:09:30Z,-1,10.0.0.99,*,0,TCP,INBOUND,BLOCK,-2,SYN_FLOOD
```

---

## 🎓 DSA Viva Performance Analysis

For university major project defenses (such as viva sessions), this project demonstrates excellent algorithmic selections:
1.  **Why use a BST for rules instead of a LinkedList?**
    *   Evaluating rules in a LinkedList is $O(n)$ in the worst case. In a balanced BST, it scales at $O(\log n)$, reducing CPU cycles during high-traffic packet streams.
2.  **Why use separate chaining instead of open addressing in the HashMap?**
    *   Separate chaining with rehashing maintains robust $O(1)$ lookups even under clustered IP network segments, eliminating collision cascading.
3.  **Why circular arrays for Stack/Queue?**
    *   Circular buffers prevent continuous dynamic memory allocations/deallocations, eliminating memory fragmentation and guaranteeing $O(1)$ push/pop boundaries.
