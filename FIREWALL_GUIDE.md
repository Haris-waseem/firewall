# 🛡️ C++ Packet Filtering Firewall — Complete Project Documentation

> **Author**: Haris | COMSATS University Islamabad
> **Project Type**: DSA Major Project — Terminal-Based Packet Filtering Firewall & Traffic Monitor
> **Language**: C++17 | **Build System**: CMake 3.10+ | **Backend**: Flat-File CSV + MongoDB (Optional)

---

## Table of Contents

1. [Project Overview](#-1-project-overview)
2. [Why So Many Folders? — Directory Structure Explained](#-2-why-so-many-folders--directory-structure-explained)
3. [Why Two Extensions? (.h vs .cpp)](#-3-why-two-extensions-h-vs-cpp)
4. [CMake & The Build System (CMakeLists.txt)](#-4-cmake--the-build-system-cmakeliststxt)
5. [Complete File-by-File & Function-by-Function Breakdown](#-5-complete-file-by-file--function-by-function-breakdown)
   - 5.1 [Enums (enums.h / enums.cpp)](#51-enums-enumsh--enumscpp)
   - 5.2 [Packet (Packet.h / Packet.cpp)](#52-packet-packeth--packetcpp)
   - 5.3 [Rule (Rule.h / Rule.cpp)](#53-rule-ruleh--rulecpp)
   - 5.4 [RuleNode (RuleNode.h)](#54-rulenode-rulenodeh)
   - 5.5 [FirewallStats (FirewallStats.h)](#55-firewallstats-firewallstatsh)
   - 5.6 [LinkedList (LinkedList.h / LinkedList.cpp)](#56-linkedlist-linkedlisth--linkedlistcpp)
   - 5.7 [Binary Search Tree (BST.h / BST.cpp)](#57-binary-search-tree-bsth--bstcpp)
   - 5.8 [HashMap (HashMap.h / HashMap.cpp)](#58-hashmap-hashmaph--hashmapcpp)
   - 5.9 [Stack (Stack.h / Stack.cpp)](#59-stack-stackh--stackcpp)
   - 5.10 [Queue (Queue.h / Queue.cpp)](#510-queue-queueh--queuecpp)
   - 5.11 [ILogger (ILogger.h)](#511-ilogger-iloggerh)
   - 5.12 [FileLogger (FileLogger.h / FileLogger.cpp)](#512-filelogger-fileloggerh--fileloggercpp)
   - 5.13 [MongoConfig (MongoConfig.h)](#513-mongoconfig-mongoconfigh)
   - 5.14 [MongoLogger (MongoLogger.h / MongoLogger.cpp)](#514-mongologger-mongologgerh--mongologgercpp)
   - 5.15 [TrafficMonitor (TrafficMonitor.h / TrafficMonitor.cpp)](#515-trafficmonitor-trafficmonitorh--trafficmonitorcpp)
   - 5.16 [RuleEngine (RuleEngine.h / RuleEngine.cpp)](#516-ruleengine-ruleengineh--ruleenginecpp)
   - 5.17 [PacketProcessor (PacketProcessor.h / PacketProcessor.cpp)](#517-packetprocessor-packetprocessorh--packetprocessorcpp)
   - 5.18 [PacketSimulator (PacketSimulator.h / PacketSimulator.cpp)](#518-packetsimulator-packetsimulatorh--packetsimulator-cpp)
   - 5.19 [AdminCLI (AdminCLI.h / AdminCLI.cpp)](#519-admincli-adminclih--adminclicpp)
   - 5.20 [main.cpp — Entry Point](#520-maincpp--entry-point)
6. [All Functionalities Used in This Project](#-6-all-functionalities-used-in-this-project)
7. [MongoDB Backend — Complete Explanation](#-7-mongodb-backend--complete-explanation)
8. [CLI Command Scenarios — Word-by-Word Breakdown](#-8-cli-command-scenarios--word-by-word-breakdown)
9. [Why No GUI? + Proposed GUI Design](#-9-why-no-gui--proposed-gui-design)
10. [Compilation & Running Instructions](#-10-compilation--running-instructions)
11. [Frequently Asked Questions](#-11-frequently-asked-questions)

---

## 🌐 1. Project Overview

This is a **command-line Packet Filtering Firewall Simulator** written entirely in C++17. It inspects simulated network packets, decides whether to ALLOW or BLOCK them based on configurable rules, detects real-time threats (SYN floods and port scans), and logs all activity to both flat CSV files and optionally to a MongoDB database.

The project demonstrates 5 custom data structures implemented from scratch (no STL containers for core storage):
- **Singly-Linked List** — for ordered rule storage
- **Binary Search Tree (BST)** — for fast O(log n) rule matching
- **HashMap** — for instant O(1) IP whitelist/blacklist lookups
- **Stack (circular array)** — for LIFO packet history
- **Queue (circular array)** — for FIFO packet buffering

### How the Firewall Works (Packet Inspection Pipeline)

```
[ Incoming Packet ]
       │
       ▼
 1. Validation ────────► (Invalid Format?) ────────► [ BLOCK & Log Code -4 ]
       │
       ▼
 2. Queue Buffer ──────► (Queue Full Overflow?) ───► [ BLOCK & Log Code -5 ]
       │
       ▼
 3. Threat Monitor ────► (SYN Flood / Port Scan?) ──► [ Blacklist IP & Alert ]
       │
       ▼
 4. O(1) Whitelist ────► (Whitelisted Source IP?) ──► [ ALLOW & Log Code -1 ]
       │
       ▼
 5. O(1) Blacklist ────► (Blacklisted Source IP?) ──► [ BLOCK & Log Code -2 ]
       │
       ▼
 6. O(log n) BST ──────► (Found Matching Rule?) ───► [ Rule Action Decision ]
       │                                                     │
       ▼ (No Match)                                          ▼
 7. Default Policy ─────────────────────────────────► [ BLOCK / ALLOW ]
       │
       ▼
 [ Log CSV & MongoDB ] ──► [ Push to LIFO History Stack ]
```

---

## 📁 2. Why So Many Folders? — Directory Structure Explained

```
📁 Terminal/                    ← Root project folder
│
├── 📁 include/                 ← Header files (.h) — declarations, blueprints, class interfaces
│   ├── enums.h                 ← Enum types (Protocol, Direction, Action, ThreatType)
│   ├── Packet.h                ← Packet struct declaration
│   ├── Rule.h                  ← Rule struct declaration
│   ├── RuleNode.h              ← Node struct shared by LinkedList and BST
│   ├── FirewallStats.h         ← Stats counter struct (header-only, no .cpp)
│   ├── ILogger.h               ← Abstract interface for logging backends
│   ├── LinkedList.h            ← Singly-linked list class declaration
│   ├── BST.h                   ← Binary search tree class declaration
│   ├── HashMap.h               ← Hash map class declaration
│   ├── Stack.h                 ← Circular stack class declaration
│   ├── Queue.h                 ← Circular queue class declaration
│   ├── FileLogger.h            ← Flat-file logger class declaration
│   ├── MongoConfig.h           ← MongoDB configuration struct (header-only)
│   ├── MongoLogger.h           ← MongoDB logger class declaration
│   ├── TrafficMonitor.h        ← Threat detection class declaration
│   ├── RuleEngine.h            ← Central rule coordinator class declaration
│   ├── PacketProcessor.h       ← Packet pipeline processor class declaration
│   ├── PacketSimulator.h       ← Test packet generator class declaration
│   └── AdminCLI.h              ← Admin CLI controller class declaration
│
├── 📁 src/                     ← Source files (.cpp) — implementations, actual logic
│   ├── enums.cpp               ← Enum string conversion implementations
│   ├── Packet.cpp              ← Packet validation, toString, timestamp logic
│   ├── Rule.cpp                ← Rule matching, serialisation, parsing logic
│   ├── LinkedList.cpp          ← Linked list insert, remove, find, print logic
│   ├── BST.cpp                 ← BST insert, match, remove, traversal logic
│   ├── HashMap.cpp             ← Hash map djb2 hash, insert, get, rehash logic
│   ├── Stack.cpp               ← Circular stack push, pop, peek, print logic
│   ├── Queue.cpp               ← Circular queue enqueue, dequeue logic
│   ├── FileLogger.cpp          ← CSV logging, rules.conf read/write logic
│   ├── MongoLogger.cpp         ← MongoDB CRUD operations + stub fallbacks
│   ├── TrafficMonitor.cpp      ← SYN flood & port scan detection logic
│   ├── RuleEngine.cpp          ← Whitelist/Blacklist/BST evaluation pipeline
│   ├── PacketProcessor.cpp     ← Full packet processing orchestration logic
│   ├── PacketSimulator.cpp     ← Test packet creation logic
│   ├── AdminCLI.cpp            ← REPL loop, command parsing & dispatch logic
│   └── main.cpp                ← Entry point — initialises all components
│
├── 📁 build/                   ← Compiled output folder (generated by CMake)
│   ├── Firewall.exe            ← The compiled executable (964 KB)
│   ├── Makefile                ← Auto-generated build instructions
│   ├── CMakeCache.txt          ← CMake configuration cache
│   ├── CMakeFiles/             ← CMake internal build metadata
│   ├── rules.conf              ← Runtime copy of rules config (used by Firewall.exe)
│   ├── firewall.log            ← Runtime copy of log file
│   ├── libmongocxx.dll         ← MongoDB C++ driver shared library
│   ├── libbsoncxx.dll          ← BSON C++ serialisation library
│   ├── libmongoc2.dll          ← MongoDB C driver shared library
│   ├── libbson2.dll            ← BSON C serialisation library
│   ├── libutf8proc.dll         ← UTF-8 processing library (MongoDB dependency)
│   └── libz.dll                ← Zlib compression library (MongoDB dependency)
│
├── 📁 .vscode/                 ← VS Code IDE configuration
│   ├── tasks.json              ← Build task definitions (Ctrl+Shift+B to build)
│   └── launch.json             ← Debugger configurations (F5 to debug)
│
├── 📄 CMakeLists.txt           ← Build system master configuration (47 lines)
├── 📄 rules.conf               ← Persistent firewall rule/IP-list database
├── 📄 firewall.log             ← CSV format runtime event log
├── 📄 README.md                ← Project overview
├── 📄 srs_text.txt             ← Software Requirements Specification (text export)
├── 📄 sds_text.txt             ← Software Design Specification (text export)
├── 📄 Firewall_SRS_Haris.docx  ← SRS document (Word format)
└── 📄 Firewall_SDS_Haris.docx  ← SDS document (Word format)
```

### Why these specific folders exist:

| Folder | Purpose | Why it's needed |
|--------|---------|-----------------|
| `include/` | Stores all `.h` header files containing class declarations, struct definitions, and function signatures | Separates the "blueprint" from the "construction". The compiler needs to know *what* exists (types, function signatures) before it can compile *how* it works. This also enables multiple `.cpp` files to share the same declarations without code duplication. Industry standard for C/C++ projects. |
| `src/` | Stores all `.cpp` source files containing the actual implementation logic | Keeps implementation details private and separate. When you change a `.cpp` file, only that single file needs recompilation — not the entire project. This saves compilation time dramatically on large projects. |
| `build/` | Contains everything CMake generates during compilation: object files, makefiles, the final `.exe`, and any runtime DLLs | Keeps the root project directory clean. Without a dedicated build folder, your source tree would be polluted with dozens of `.o`, `.obj`, cache files, and generated makefiles. You can safely delete this entire folder and rebuild from scratch. |
| `.vscode/` | VS Code editor configuration for build tasks and debugging | Allows you to press `Ctrl+Shift+B` to compile and `F5` to debug directly from VS Code without typing terminal commands. Contains `tasks.json` (defines how to build) and `launch.json` (defines how to launch the debugger). |

---

## 🔧 3. Why Two Extensions? (.h vs .cpp)

In C++, code is split into two file types:

### Header Files (`.h`) — The Blueprint
- Contains **declarations**: class definitions, struct layouts, function signatures, enum types
- Tells the compiler *"these things exist and have these shapes"*
- Included by multiple `.cpp` files using `#include`
- Uses `#pragma once` to prevent being included twice in the same compilation unit

### Source Files (`.cpp`) — The Construction
- Contains **definitions**: the actual code that runs — function bodies, algorithm logic, I/O operations
- Each `.cpp` file is compiled independently into an **object file** (`.o` or `.obj`)
- The linker then combines all object files into the final executable

### Why not put everything in one file?
1. **Compilation speed**: If you change `HashMap.cpp`, only that one file recompiles. If everything was in one file, the entire 2,000+ line project would recompile every time.
2. **Circular dependencies**: `Packet.h` needs `enums.h`, `Rule.h` needs `Packet.h`, `BST.h` needs `Rule.h`. Headers let the compiler resolve these chains without seeing implementation details.
3. **Encapsulation**: Other classes only need to know *what* a HashMap can do (from `HashMap.h`), not *how* it does it (in `HashMap.cpp`).
4. **Team collaboration**: Different developers can work on different `.cpp` files simultaneously without merge conflicts.

### Files that are header-only (no matching .cpp):
- `RuleNode.h` — Simple struct, no complex logic needed
- `FirewallStats.h` — Simple struct with one inline `print()` method
- `MongoConfig.h` — Simple struct holding 3 configuration strings
- `ILogger.h` — Pure abstract interface (all methods are `= 0`)

---

## 🏗️ 4. CMake & The Build System (CMakeLists.txt)

### What is CMake?
CMake is a **cross-platform build system generator**. It reads `CMakeLists.txt` and generates the actual platform-specific build files (Makefiles on Linux, Visual Studio solutions on Windows, Xcode projects on macOS).

### Why was CMake chosen for this project?
1. **Multi-file project**: This project has 16 source files. Manually typing `g++ src/enums.cpp src/Packet.cpp src/Rule.cpp ...` every time is error-prone and tedious.
2. **Optional MongoDB**: CMake's `option()` and `if()` commands let you toggle MongoDB on/off with a single flag (`-DWITH_MONGODB=ON`), conditionally linking libraries and setting preprocessor defines.
3. **Cross-platform**: The same `CMakeLists.txt` works on Windows (MSVC, MinGW), Linux (GCC), and macOS (Clang) without modification.
4. **IDE integration**: VS Code, CLion, Visual Studio all natively understand CMake projects.

### Line-by-Line Breakdown of CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.10)          # Line 1: Requires CMake 3.10 or newer
project(PacketFilteringFirewall VERSION 1.0)   # Line 2: Names the project and sets version

set(CMAKE_CXX_STANDARD 17)                    # Line 4: Use C++17 language standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)           # Line 5: Fail if compiler doesn't support C++17

# Lines 8-24: List every .cpp file that needs to be compiled
set(SOURCES
    src/enums.cpp
    src/Packet.cpp
    src/Rule.cpp
    src/LinkedList.cpp
    src/BST.cpp
    src/HashMap.cpp
    src/Stack.cpp
    src/Queue.cpp
    src/FileLogger.cpp
    src/MongoLogger.cpp
    src/TrafficMonitor.cpp
    src/RuleEngine.cpp
    src/PacketProcessor.cpp
    src/PacketSimulator.cpp
    src/AdminCLI.cpp
    src/main.cpp
)

add_executable(Firewall ${SOURCES})            # Line 28: Create an executable called "Firewall"
                                               #          from all listed source files

target_include_directories(Firewall PRIVATE include)  # Line 31: Tell the compiler to look
                                                       #          in the "include/" folder for
                                                       #          header files

# Lines 37-46: MongoDB optional integration
option(WITH_MONGODB "Compile with MongoDB drivers" OFF)  # Default: MongoDB is OFF
if (WITH_MONGODB)
    find_package(mongocxx CONFIG REQUIRED)     # Find the MongoDB C++ driver
    find_package(bsoncxx CONFIG REQUIRED)      # Find the BSON C++ library
    target_compile_definitions(Firewall PRIVATE USE_MONGODB)  # Define USE_MONGODB macro
    target_link_libraries(Firewall PRIVATE mongo::mongocxx_shared mongo::bsoncxx_shared)
    message(STATUS "Configuring build with MongoDB driver support.")
else()
    message(STATUS "Configuring build with flat-file persistence (MongoDB driver disabled).")
endif()
```

### What would happen if CMakeLists.txt didn't exist?
Without it, you'd have to:
1. Manually type the entire compilation command every time:
   ```
   g++ -std=c++17 src/enums.cpp src/Packet.cpp src/Rule.cpp src/LinkedList.cpp src/BST.cpp src/HashMap.cpp src/Stack.cpp src/Queue.cpp src/FileLogger.cpp src/MongoLogger.cpp src/TrafficMonitor.cpp src/RuleEngine.cpp src/PacketProcessor.cpp src/PacketSimulator.cpp src/AdminCLI.cpp src/main.cpp -Iinclude -o Firewall.exe
   ```
2. If you want MongoDB, you'd also need to manually find and specify the library paths:
   ```
   g++ ... -DUSE_MONGODB -I/path/to/mongocxx/include -L/path/to/mongocxx/lib -lmongocxx -lbsoncxx
   ```
3. There would be no incremental compilation — every file recompiles every time, even if you only changed one line.
4. Moving to a different OS or compiler would require rewriting these commands entirely.

---

## 📋 5. Complete File-by-File & Function-by-Function Breakdown

### 5.1 Enums (`enums.h` / `enums.cpp`)

**Purpose**: Defines the 4 core enumeration types used across the entire project and their string conversion utilities.

#### `enums.h` — Declarations
```cpp
enum class Protocol  { TCP, UDP, ICMP, ANY };      // Network protocols the firewall understands
enum class Direction { INBOUND, OUTBOUND, BOTH };   // Traffic direction filter
enum class Action    { ALLOW, BLOCK, LOG_ONLY };    // What to do with a matched packet
enum class ThreatType{ NONE, SYN_FLOOD, PORT_SCAN };// Detected threat categories
```

- `Protocol::ANY` means "match any protocol" (wildcard)
- `Direction::BOTH` means "match regardless of direction" (wildcard)
- `Action::LOG_ONLY` means "don't block or allow — just record it"
- `ThreatType::NONE` means "no threat detected"

#### `enums.cpp` — Implementations (8 functions)

| Function | What it does | Line-by-line |
|----------|-------------|--------------|
| `protocolToStr(Protocol p)` | Converts enum to string. `TCP→"TCP"`, `UDP→"UDP"`, etc. Uses a `switch` statement. | Used whenever a protocol needs to be printed or saved to a file. |
| `strToProtocol(const string& s)` | Converts a user-typed string back to enum. First converts input to uppercase using `std::transform`, then compares. Throws `invalid_argument` if unrecognized. | Used when parsing CLI commands like `add-rule ... TCP ...`. |
| `directionToStr(Direction d)` | Same pattern — converts `INBOUND→"INBOUND"`, `OUTBOUND→"OUTBOUND"`, `BOTH→"BOTH"`. | Used for logging and display. |
| `strToDirection(const string& s)` | Accepts shorthand too: `"IN"→INBOUND`, `"OUT"→OUTBOUND`. Throws on unknown. | Used when parsing CLI input. |
| `actionToStr(Action a)` | Converts `ALLOW→"ALLOW"`, `BLOCK→"BLOCK"`, `LOG_ONLY→"LOG_ONLY"`. | Used everywhere for display. |
| `strToAction(const string& s)` | Accepts `"LOG"` as shorthand for `LOG_ONLY`. Throws on unknown. | Used when parsing CLI input. |
| `threatToStr(ThreatType t)` | Converts threat types to strings for logging. | Used in `FileLogger::logThreat()`. |
| `strToThreat(const string& s)` | Converts strings back. Returns `NONE` for any unrecognized input (doesn't throw). | Used when loading from config. |

---

### 5.2 Packet (`Packet.h` / `Packet.cpp`)

**Purpose**: Represents a single network packet flowing through the firewall.

#### Struct Fields
```cpp
int       packetID    = 0;          // Unique sequential ID assigned by PacketSimulator
string    sourceIP;                 // Sender's IP address (e.g., "192.168.1.50")
string    destIP;                   // Destination IP address (e.g., "10.0.0.1")
int       destPort    = 0;          // Target port number (e.g., 80 for HTTP, 22 for SSH)
Protocol  protocol    = Protocol::TCP;   // Which network protocol
Direction direction   = Direction::INBOUND; // Traffic direction
bool      isSYN       = false;      // Is this a TCP SYN handshake packet?
int       payloadSize = 0;          // Size of data payload in bytes
string    timestamp;                // ISO 8601 timestamp when packet was created
```

#### Functions

**`isValid() const`** — Lines 13-37 of Packet.cpp
- Validates that the port is between 0 and 65535
- Validates that both `sourceIP` and `destIP` follow the `X.X.X.X` format (4 octets, each 0-255)
- Uses a lambda `checkIP` that splits the IP string by `.` delimiters, counts parts, and validates each octet
- Returns `false` if any check fails — used by `PacketProcessor::process()` to reject malformed packets early

**`toString() const`** — Lines 40-49
- Builds a human-readable summary string like: `[Pkt#1] 192.168.1.50 -> 10.0.0.1:80 TCP INBOUND @ 2026-05-31T13:09:20Z`
- Appends ` SYN` flag if `isSYN` is true
- Uses `ostringstream` for efficient string building

**`currentTimestamp()` (static)** — Lines 52-64
- Gets the current system time using `std::chrono::system_clock::now()`
- Converts to `time_t`, then to a `tm` struct
- Uses platform-specific safe functions: `localtime_s` on Windows, `localtime_r` on Linux/Mac
- Formats as ISO 8601: `2026-06-11T21:00:00Z`

---

### 5.3 Rule (`Rule.h` / `Rule.cpp`)

**Purpose**: Represents one filtering rule in the firewall's ruleset.

#### Struct Fields
```cpp
int         ruleID      = 0;        // Unique ID assigned sequentially
int         priority    = 100;      // Lower number = higher precedence (10 beats 100)
string      sourceIP    = "*";      // "*" means match any IP
int         destPort    = -1;       // -1 means match any port
Protocol    protocol    = Protocol::ANY;
Direction   direction   = Direction::BOTH;
Action      action      = Action::BLOCK;
string      description = "";       // Human-readable description
bool        enabled     = true;     // Can be toggled on/off without deleting
int         hitCount    = 0;        // How many packets this rule has matched
```

#### Functions

**`matches(const Packet& p) const`** — Lines 13-20 of Rule.cpp
```cpp
if (!enabled)                                         return false; // Disabled rules never match
if (sourceIP  != "*"         && sourceIP  != p.sourceIP)  return false; // IP mismatch
if (destPort  != -1          && destPort  != p.destPort)   return false; // Port mismatch
if (protocol  != Protocol::ANY  && protocol  != p.protocol)  return false; // Protocol mismatch
if (direction != Direction::BOTH && direction != p.direction) return false; // Direction mismatch
return true; // All non-wildcard fields matched!
```
This is the core matching function. Each field is checked only if it's not a wildcard (`*`, `-1`, `ANY`, `BOTH`). The moment any field doesn't match, it short-circuits and returns `false`.

**`toConfigLine() const`** — Lines 24-35
- Serialises the rule into a single text line for `rules.conf`:
  `001 010 ALLOW    BOTH     ANY   192.168.1.100         -1 Whitelist Admin Machine`
- Uses `setw` and `setfill` for alignment

**`fromConfigLine(const string& line)` (static)** — Lines 38-56
- Parses one line from `rules.conf` back into a `Rule` object
- Reads fields in order: ruleID, priority, action, direction, protocol, sourceIP, destPort
- Everything after port is treated as the description string
- Throws `invalid_argument` on malformed lines (caught by `FileLogger::loadRules()`)

**`toString() const`** — Lines 59-72
- Formatted display string for the `list-rules` table output
- Shows: ID | Priority | Action | Direction | Protocol | Source IP | Port | Hits | Status | Description

---

### 5.4 RuleNode (`RuleNode.h`)

**Purpose**: The internal node structure shared by both the LinkedList and the BST.

```cpp
struct RuleNode {
    Rule      rule;              // Owned Rule data (stored by value, not pointer)
    RuleNode* next  = nullptr;   // LinkedList uses this for forward traversal
    RuleNode* left  = nullptr;   // BST uses this for left child
    RuleNode* right = nullptr;   // BST uses this for right child

    explicit RuleNode(const Rule& r) : rule(r) {}  // Constructor copies the Rule in
};
```

**Key Design Decision**: Although both LinkedList and BST use `RuleNode`, they each allocate their own independent copies. The BST stores a copy of the rule (by value inside the node), and the LinkedList stores its own copy. When a rule is updated via `RuleEngine`, **both** the LinkedList node and the BST must be updated independently — this is handled by `RuleEngine::rebuildBST()`.

---

### 5.5 FirewallStats (`FirewallStats.h`)

**Purpose**: Plain data struct holding all runtime counters. Header-only (no `.cpp` file needed).

```cpp
int totalProcessed      = 0;   // Total packets that entered the pipeline
int totalBlocked        = 0;   // Packets that were blocked
int totalAllowed        = 0;   // Packets that were allowed
int totalLogged         = 0;   // Packets logged to file/database
int synFloodsDetected   = 0;   // Number of SYN flood threats detected
int portScansDetected   = 0;   // Number of port scan threats detected
int queueOverflows      = 0;   // Packets dropped because buffer was full
string startTime;              // Timestamp when firewall started
```

**`print() const`**: Renders a beautiful box-drawn statistics summary using Unicode box-drawing characters (`┌`, `│`, `├`, `└`).

---

### 5.6 LinkedList (`LinkedList.h` / `LinkedList.cpp`)

**Purpose**: Stores firewall rules in a singly-linked list, maintaining ascending priority order. Used for sequential display, saving to config files, and bulk loading.

#### Key Functions — Line-by-Line

**`insert(const Rule& r)`** — Lines 16-25
```cpp
RuleNode* node = new RuleNode(r);    // Allocate new node on heap with Rule copy
if (!head_) {                        // If list is empty...
    head_ = tail_ = node;            //   new node becomes both head and tail
} else {                             // Otherwise...
    tail_->next = node;              //   attach after current tail
    tail_ = node;                    //   update tail pointer
}
size_++;                             // Increment size counter
```
**Complexity**: O(1) — constant time tail insertion using the `tail_` pointer.

**`insertSorted(const Rule& r)`** — Lines 30-56
```cpp
RuleNode* node = new RuleNode(r);
size_++;

// Check if new node goes before head (highest priority)
if (!head_ || r.priority < head_->rule.priority ||
    (r.priority == head_->rule.priority && r.ruleID < head_->rule.ruleID)) {
    node->next = head_;
    head_ = node;
    if (size_ == 1) tail_ = node;
    return;
}

// Walk the list to find insertion point
RuleNode* prev = head_;
RuleNode* curr = head_->next;
while (curr) {
    if (r.priority < curr->rule.priority ||                        // Lower priority number wins
        (r.priority == curr->rule.priority && r.ruleID < curr->rule.ruleID)) {  // Tie-break by ID
        break;
    }
    prev = curr;
    curr = curr->next;
}
node->next = curr;          // Insert between prev and curr
prev->next = node;
if (!curr) tail_ = node;   // If inserted at end, update tail
```
**Complexity**: O(n) — must scan linearly to find the correct position.

**`remove(int ruleID)`** — Lines 59-76
- Walks the list tracking `prev` and `curr` pointers
- When found: rewires `prev->next` to skip over `curr`, deletes `curr`
- Updates `tail_` if the removed node was the tail
- **Complexity**: O(n)

**`find(int ruleID)`** — Lines 79-95
- Linear scan comparing `curr->rule.ruleID` to the target
- Returns a pointer to the Rule if found, `nullptr` if not
- Two versions: mutable and `const`
- **Complexity**: O(n)

**`printAll() const`** — Lines 98-124
- Prints a formatted table header (ID | Pri | Action | Dir | Proto | Source IP | Port | Hits | Status | Description)
- Walks the list calling `rule.toString()` on each node
- Shows total rule count at the bottom

**`toVector() const`** — Lines 127-136
- Converts the linked list to a `std::vector<Rule>` for easy iteration
- Used by `RuleEngine::getAllRules()` and `rebuildBST()`

**`clear()`** — Lines 139-148
- Walks the list deleting every node to prevent memory leaks
- Resets `head_`, `tail_` to `nullptr` and `size_` to 0

---

### 5.7 Binary Search Tree (`BST.h` / `BST.cpp`)

**Purpose**: Indexes rules by priority value for fast O(log n) packet evaluation. The in-order traversal visits rules from highest precedence (lowest priority number) to lowest precedence.

#### Key Functions — Line-by-Line

**`insert(const Rule& r)` → `insertNode(node, r)`** — Lines 21-41
```cpp
if (!node) return new RuleNode(r);              // Base case: empty spot, create node

if (r.priority < node->rule.priority)           // New rule has higher precedence
    node->left  = insertNode(node->left,  r);   //   → go left
else if (r.priority > node->rule.priority)      // New rule has lower precedence
    node->right = insertNode(node->right, r);   //   → go right
else {                                          // Same priority — tie-break by ruleID
    if (r.ruleID < node->rule.ruleID)
        node->left  = insertNode(node->left,  r);
    else
        node->right = insertNode(node->right, r);
}
return node;
```
**Complexity**: O(log n) average, O(n) worst case if tree degenerates.

**`findBestMatch(const Packet& p)` → `findMatch(node, p)`** — Lines 44-60
```cpp
if (!node) return nullptr;                       // Base case: no more nodes

Rule* found = findMatch(node->left, p);          // Step 1: Search LEFT first (higher precedence)
if (found) return found;                         // Found a match! Return immediately

if (node->rule.matches(p)) return &node->rule;   // Step 2: Check THIS node

return findMatch(node->right, p);                // Step 3: Search RIGHT (lower precedence)
```
This is an **in-order traversal** (Left → Root → Right). Because lower priority numbers are stored in left subtrees, the first match found during in-order traversal is guaranteed to be the highest-precedence rule.

**Complexity**: O(log n) average.

**`remove(int ruleID)` → `removeNode(node, ruleID, found)`** — Lines 63-96
- Since the BST is keyed on *priority* but we're searching by *ruleID*, this must do a full tree traversal — O(n)
- When found, handles three cases:
  - **No children**: Delete node, return `nullptr`
  - **One child**: Replace node with its child
  - **Two children**: Find in-order successor (smallest node in right subtree), copy its data up, then delete the successor

**`height()` / `isBalanced()`** — Lines 116-133
- `height()` recursively computes tree depth: `1 + max(left_height, right_height)`
- `isBalanced()` checks if `|left_height - right_height| <= 1` at every node
- Useful for DSA viva demonstrations

**`clear()` → `clearHelper(node)`** — Lines 136-146
- Post-order traversal (Left → Right → Root) to safely delete all nodes
- Post-order ensures children are deleted before their parent

---

### 5.8 HashMap (`HashMap.h` / `HashMap.cpp`)

**Purpose**: Provides O(1) average-time lookups for IP blacklist/whitelist checking and SYN/port-scan counters.

#### Design Details
- **Hash function**: Dan Bernstein's **djb2** algorithm
- **Collision resolution**: Separate chaining (each bucket is a `std::list` of key-value pairs)
- **Initial capacity**: 1024 buckets (power of 2)
- **Auto-rehash**: Doubles bucket count when load factor exceeds 0.75

#### Key Functions — Line-by-Line

**`hash(const string& key) const`** — Lines 20-25
```cpp
unsigned long h = 5381;                          // djb2 magic constant
for (unsigned char c : key)
    h = ((h << 5) + h) ^ c;                     // h * 33 ^ c — bit shift is faster than multiply
return static_cast<int>(h % static_cast<unsigned long>(bucketCount_));  // Modulo to fit bucket index
```
The djb2 hash has excellent avalanche properties — similar IP strings like `192.168.1.1` and `192.168.1.2` produce very different hash values.

**`insert(const string& key, int value)`** — Lines 28-36
```cpp
if (loadFactor() > 0.75f) rehash();              // Check if rehash needed before inserting
int idx = hash(key);                              // Compute bucket index
for (auto& pair : buckets_[idx]) {                // Scan bucket for existing key
    if (pair.first == key) { pair.second = value; return; }  // Update if found
}
buckets_[idx].push_back({key, value});            // New key — append to bucket chain
count_++;
```

**`increment(const string& key)`** — Lines 66-75
- If key exists: increments its integer value by 1
- If key doesn't exist: inserts it with value 1
- Used by `TrafficMonitor` to count SYN packets and distinct ports per IP

**`topN(int n) const`** — Lines 78-100
- Uses a **min-heap** (priority queue) to efficiently find the N entries with the highest values
- Iterates all entries, maintaining a heap of size N
- Final result is sorted descending by value
- **Complexity**: O(N log n) where N = total entries

**`rehash()`** — Lines 119-134
- Creates a new bucket array with double the size
- Re-hashes and re-inserts every existing entry into the new array
- Replaces old buckets with the new array

---

### 5.9 Stack (`Stack.h` / `Stack.cpp`)

**Purpose**: LIFO (Last-In-First-Out) circular buffer for storing recent packet history.

#### Design
- Fixed-capacity circular array (default: 100 entries)
- When full, new pushes overwrite the oldest entries without shifting memory
- Uses modular arithmetic for index wrapping

#### Key Functions

**`push(const Packet& p)`** — Lines 18-24
```cpp
top_ = (top_ + 1) % capacity_;    // Advance top pointer, wrap around at capacity
items_[top_] = p;                  // Store packet at new top position
if (count_ < capacity_) {
    count_++;                      // Only increment count if not yet full
}
// If full, count_ stays at capacity_ — oldest entry silently overwritten
```
**Complexity**: O(1) — no memory allocation, no shifting.

**`pop()`** — Lines 27-35
```cpp
if (isEmpty()) throw std::runtime_error("Stack underflow: History is empty.");
Packet p = items_[top_];                      // Grab the top packet
top_ = (top_ - 1 + capacity_) % capacity_;   // Move top backwards (with wrap)
count_--;
return p;
```
The expression `(top_ - 1 + capacity_) % capacity_` handles the wrap-around elegantly: if `top_` is 0, it wraps to `capacity_ - 1`.

**`printTop(int n) const`** — Lines 46-56
```cpp
int limit = (n < count_) ? n : count_;
for (int i = 0; i < limit; i++) {
    int idx = (top_ - i + capacity_) % capacity_;   // Step backwards from top
    std::cout << "  " << items_[idx].toString() << "\n";
}
```
Walks backwards from `top_` using modular arithmetic to display the most recent N packets.

---

### 5.10 Queue (`Queue.h` / `Queue.cpp`)

**Purpose**: FIFO (First-In-First-Out) circular buffer for buffering incoming packets before processing.

#### Key Functions

**`enqueue(const Packet& p)`** — Lines 18-27
```cpp
if (isFull()) {
    overflowCount_++;    // Track dropped packets
    return false;        // Signal that the packet was dropped
}
rear_ = (rear_ + 1) % capacity_;   // Advance rear pointer with wrap
items_[rear_] = p;                  // Store packet at new rear
count_++;
return true;
```

**`dequeue()`** — Lines 30-38
```cpp
if (isEmpty()) throw std::runtime_error("Queue underflow: Buffer is empty.");
Packet p = items_[front_];                    // Grab the front packet
front_ = (front_ + 1) % capacity_;           // Advance front pointer with wrap
count_--;
return p;
```

---

### 5.11 ILogger (`ILogger.h`)

**Purpose**: Abstract interface (pure virtual class) that defines the contract all logging backends must satisfy.

```cpp
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void logEvent(const Packet& p, Action action, int matchedRuleID = -1) = 0;
    virtual void logThreat(const string& ip, ThreatType t) = 0;
    virtual vector<string> queryByIP(const string& ip) = 0;
    virtual vector<string> queryByAction(const string& action) = 0;
    virtual vector<string> queryLastN(int minutes) = 0;
};
```

Both `FileLogger` and `MongoLogger` inherit from this interface. This means the rest of the system can log without knowing which backend is active — a clean application of **polymorphism**.

---

### 5.12 FileLogger (`FileLogger.h` / `FileLogger.cpp`)

**Purpose**: Flat-file persistence backend. Writes CSV logs to `firewall.log` and manages `rules.conf`.

#### Key Functions

**Constructor** — Opens `firewall.log` in append mode. The file stream stays open for performance (avoids repeated open/close for every packet).

**`logEvent()`** — Writes one CSV line: `timestamp,packetID,sourceIP,destIP,destPort,protocol,direction,action,matchedRuleID,threatType`. Calls `flush()` after each write to ensure data hits disk immediately.

**`logThreat()`** — Writes a special CSV line with packetID=-1, destIP=*, port=0, marking the threat type.

**`queryByIP(ip)`** — Opens `firewall.log` for reading, splits each line by commas, checks if field index 2 (sourceIP) matches the query.

**`queryByAction(action)`** — Same approach, checks field index 7 (action field).

**`queryLastN(minutes)`** — Parses the timestamp from each log line, compares against current time, includes lines within the time window.

**`saveRules(rules, defaultPolicy)`** — Rewrites the entire `rules.conf` file. Preserves blacklist and whitelist by loading them first, then writes all three sections (`[RULES]`, `[BLACKLIST]`, `[WHITELIST]`).

**`loadRules(outDefaultPolicy)`** — Parses `rules.conf` section by section. Detects `[RULES]`, `[BLACKLIST]`, `[WHITELIST]` headers. Parses rule lines using `Rule::fromConfigLine()`. Extracts the `DEFAULT_POLICY` line.

---

### 5.13 MongoConfig (`MongoConfig.h`)

**Purpose**: Simple configuration struct for MongoDB connection parameters. Header-only.

```cpp
struct MongoConfig {
    string mongoURI  = "mongodb://localhost:27017";  // Default local MongoDB URI
    string dbName    = "firewall_db";                // Database name
    bool dualWriteMode = true;                       // Write to both MongoDB AND flat-file
};
```

---

### 5.14 MongoLogger (`MongoLogger.h` / `MongoLogger.cpp`)

**Purpose**: MongoDB persistence layer with graceful degradation.

#### The Dual-Mode Architecture (`#ifdef USE_MONGODB`)

This file contains **two complete implementations** separated by a preprocessor conditional:

**When `USE_MONGODB` is defined** (Lines 11-301):
- Full MongoDB driver integration
- Creates a `mongocxx::instance` (singleton, exactly once per process)
- Connects to `mongodb://localhost:27017`
- Uses the `firewall_db` database
- CRUD operations on 5 collections: `trafficlog`, `threats`, `rules`, `blacklist`, `whitelist`
- Builds BSON documents using the stream builder API
- All operations wrapped in try-catch for `mongocxx::exception`

**When `USE_MONGODB` is NOT defined** (Lines 302-328, the `#else` block):
- Stub implementations that do nothing
- Constructor prints: `"[MongoLogger] MongoDB not available — using flat-file persistence."`
- All methods return empty results or do nothing
- **This is the graceful degradation** — the project compiles and runs perfectly without MongoDB drivers installed

#### MongoDB Collections

| Collection | Purpose | Document Fields |
|------------|---------|-----------------|
| `trafficlog` | Stores every packet event | timestamp, sourceIP, destinationIP, port, protocol, direction, action, matchedRuleID |
| `threats` | Records detected security threats | timestamp, sourceIP, threatType |
| `rules` | Mirrors the active ruleset | ruleID, action, direction, protocol, sourceIP, port, priority, description |
| `blacklist` | Explicitly blocked IPs | ip, timestamp |
| `whitelist` | Explicitly trusted IPs | ip, timestamp |

---

### 5.15 TrafficMonitor (`TrafficMonitor.h` / `TrafficMonitor.cpp`)

**Purpose**: Real-time threat detection using sliding time-window analysis.

#### Internal State (3 HashMaps)
```
synCounters_      : sourceIP → count of SYN packets in current window
portScanCounters_ : "sourceIP:port" → 1 (presence flag — deduplicates port probes)
portCountPerIP_   : sourceIP → count of distinct destination ports probed
```

#### `inspect(const Packet& p)` — Lines 20-45
```cpp
// Check if time window has expired → reset all counters
time_t now = time(nullptr);
if (difftime(now, windowStart_) >= windowSeconds_) {
    resetWindow();
}

// SYN Flood Detection: Count TCP SYN packets per source IP
if (p.protocol == Protocol::TCP && p.isSYN) {
    synCounters_.increment(p.sourceIP);        // Increment SYN count for this IP
    if (synCounters_.get(p.sourceIP) > synThreshold_) {
        return ThreatType::SYN_FLOOD;          // Too many SYNs! It's a flood.
    }
}

// Port Scan Detection: Count distinct destination ports per source IP
string key = p.sourceIP + ":" + to_string(p.destPort);
if (!portScanCounters_.contains(key)) {        // Only count each IP:port pair once
    portScanCounters_.insert(key, 1);
    portCountPerIP_.increment(p.sourceIP);     // Increment distinct port count
    if (portCountPerIP_.get(p.sourceIP) > portScanThreshold_) {
        return ThreatType::PORT_SCAN;          // Too many ports probed! It's a scan.
    }
}

return ThreatType::NONE;                       // No threat detected
```

Default thresholds: SYN=100 packets, PortScan=20 distinct ports, Window=10 seconds.

---

### 5.16 RuleEngine (`RuleEngine.h` / `RuleEngine.cpp`)

**Purpose**: The central coordinator owning all rule data structures. Orchestrates whitelist, blacklist, LinkedList, and BST.

#### Internal State
```cpp
LinkedList ruleList_;              // Primary rule storage (ordered)
BST        ruleBST_;               // Secondary index for fast matching
HashMap    blacklist_;             // O(1) IP blacklist
HashMap    whitelist_;             // O(1) IP whitelist
int        nextRuleID_ = 1;       // Auto-incrementing rule ID counter
Action     defaultPolicy_ = BLOCK; // What happens when no rule matches
```

#### `evaluate(const Packet& p, int& matchedRuleID)` — Lines 13-43
```cpp
// Step 1: Whitelist Check — O(1) HashMap lookup
if (whitelist_.contains(p.sourceIP)) {
    matchedRuleID = -1;                    // Code -1 = "Whitelisted"
    return Action::ALLOW;
}

// Step 2: Blacklist Check — O(1) HashMap lookup
if (blacklist_.contains(p.sourceIP)) {
    matchedRuleID = -2;                    // Code -2 = "Blacklisted"
    return Action::BLOCK;
}

// Step 3: BST Rule Matching — O(log n) tree traversal
Rule* bstMatch = ruleBST_.findBestMatch(p);
if (bstMatch) {
    matchedRuleID = bstMatch->ruleID;      // Actual rule ID
    bstMatch->hitCount++;                   // Increment hit counter in BST copy
    Rule* listMatch = ruleList_.find(bstMatch->ruleID);
    if (listMatch) listMatch->hitCount++;  // Also increment in LinkedList copy
    return bstMatch->action;
}

// Step 4: Default Policy — No rule matched
matchedRuleID = -3;                        // Code -3 = "Default policy applied"
return defaultPolicy_;
```

#### `addRule(Rule r)` — Lines 46-56
- Auto-assigns `ruleID` if not set (or updates `nextRuleID_` if importing from config)
- Inserts into `ruleList_` (sorted by priority)
- Calls `rebuildBST()` to keep the BST in sync

#### `rebuildBST()` — Lines 140-148
```cpp
ruleBST_.clear();                          // Destroy old tree
vector<Rule> rules = ruleList_.toVector(); // Get all rules from linked list
for (const auto& r : rules) {
    if (r.enabled) {                       // Only insert ENABLED rules into BST
        ruleBST_.insert(r);
    }
}
```
This is called after every add/remove/update/enable/disable operation to keep the BST perfectly synchronized.

---

### 5.17 PacketProcessor (`PacketProcessor.h` / `PacketProcessor.cpp`)

**Purpose**: Orchestrates the complete packet inspection pipeline, tying together all components.

#### `process(const Packet& p)` — Lines 14-71
```cpp
stats_.totalProcessed++;                         // Step 0: Count packet

// Step 1: Validation
if (!p.isValid()) {
    logger_.logEvent(p, Action::BLOCK, -4);      // Code -4 = "Invalid packet format"
    mongoLogger_.logEvent(p, Action::BLOCK, -4);
    stats_.totalBlocked++;  stats_.totalLogged++;
    return;
}

// Step 2: Buffer Enqueue
if (!packetQueue_.enqueue(p)) {
    logger_.logEvent(p, Action::BLOCK, -5);      // Code -5 = "Queue overflow"
    mongoLogger_.logEvent(p, Action::BLOCK, -5);
    stats_.queueOverflows++;  stats_.totalBlocked++;  stats_.totalLogged++;
    return;
}

// Step 3: Dequeue for processing
Packet current = packetQueue_.dequeue();

// Step 4: Threat detection
ThreatType threat = monitor_.inspect(current);
if (threat != ThreatType::NONE) {
    engine_.addToBlacklist(current.sourceIP);     // Auto-blacklist threatening IP
    logger_.logThreat(current.sourceIP, threat);
    mongoLogger_.logThreat(current.sourceIP, threat);
    if (threat == ThreatType::SYN_FLOOD) stats_.synFloodsDetected++;
    else if (threat == ThreatType::PORT_SCAN) stats_.portScansDetected++;
}

// Step 5: Evaluate against rules
int matchedRuleID = -3;
Action decision = engine_.evaluate(current, matchedRuleID);

// Step 6: Log to BOTH backends
logger_.logEvent(current, decision, matchedRuleID);
mongoLogger_.logEvent(current, decision, matchedRuleID);
stats_.totalLogged++;

// Step 7: Update stats
if (decision == Action::BLOCK) stats_.totalBlocked++;
else stats_.totalAllowed++;

// Step 8: Push to history stack
history_.push(current);
```

---

### 5.18 PacketSimulator (`PacketSimulator.h` / PacketSimulator.cpp`)

**Purpose**: Utility for generating test packets for debugging and demonstration.

- **`createPacket()`**: Builds a fully-populated `Packet` with auto-incrementing ID and current timestamp
- **`createSYNPacket(srcIP, port)`**: Shortcut for creating TCP SYN packets (useful for flood testing)
- **`generateBurst(srcIP, count, startPort)`**: Creates a burst of packets targeting sequential ports (useful for port scan testing)

---

### 5.19 AdminCLI (`AdminCLI.h` / `AdminCLI.cpp`)

**Purpose**: The admin's command-line interface — a Read-Eval-Print Loop (REPL) that parses and dispatches commands.

#### `run()` — The REPL Loop (Lines 18-35)
```cpp
while (running_) {
    cout << "firewall> ";               // Print prompt
    if (!getline(cin, line)) break;     // Read entire line from stdin
    // Trim whitespace
    dispatch(line);                     // Parse and execute the command
}
```

#### `dispatch(input)` — Command Router (Lines 38-71)
- Tokenizes the input string into words
- Matches the first word against 21 known commands using if-else chain
- Passes remaining words as `args` vector to the appropriate handler function

#### `tokenize(input)` — Helper (Lines 549-557)
- Splits a string by whitespace using `istringstream` and `>>` operator
- Returns `vector<string>` of tokens

#### `validateIP(ip)` — Helper (Lines 74-90)
- Accepts `"*"` as valid (wildcard)
- Splits by `.`, checks for exactly 4 octets, each 0-255

#### 21 Command Handler Functions:

| Handler | Command | What it does |
|---------|---------|-------------|
| `cmdAddRule(args)` | `add-rule` | Parses 5-7 args, creates Rule, calls `engine_.addRule()` |
| `cmdDelRule(args)` | `del-rule` | Parses rule ID, calls `engine_.removeRule()` |
| `cmdUpdateRule(args)` | `update-rule` | Parses rule ID + new action, calls `engine_.updateRule()` |
| `cmdEnableRule(args)` | `enable-rule` | Calls `engine_.enableRule()` |
| `cmdDisableRule(args)` | `disable-rule` | Calls `engine_.disableRule()` |
| `cmdListRules()` | `list-rules` | Calls `engine_.listRules()` → prints formatted table |
| `cmdBlockIP(args)` | `block-ip` | Validates IP, calls `engine_.addToBlacklist()` |
| `cmdAllowIP(args)` | `allow-ip` | Validates IP, calls `engine_.addToWhitelist()` |
| `cmdRemoveBlock(args)` | `remove-block` | Calls `engine_.removeFromBlacklist()` |
| `cmdRemoveAllow(args)` | `remove-allow` | Calls `engine_.removeFromWhitelist()` |
| `cmdSetPolicy(args)` | `set-policy` | Rejects `LOG_ONLY`, calls `engine_.setDefaultPolicy()` |
| `cmdShowStats()` | `show-stats` | Calls `stats_.print()`, shows blacklist/whitelist sizes |
| `cmdShowHistory(args)` | `show-history` | Calls `history_.printTop(n)` |
| `cmdQuery(args)` | `query` | Dispatches to `logger_.queryByIP/Action/LastN()` |
| `cmdSendPacket(args)` | `send-packet` | Creates packet via simulator, calls `processor_.process()` |
| `cmdSave()` | `save` | Saves rules, blacklist, whitelist to `rules.conf` |
| `cmdLoad()` | `load` | Clears engine, reloads from `rules.conf` |
| `cmdFlushRules()` | `flush-rules` | Calls `engine_.clearAll()` — wipes everything |
| `cmdSetThreshold(args)` | `set-threshold` | Configures SYN/portscan/window thresholds |
| `cmdResetThreats()` | `reset-threats` | Calls `monitor_.resetWindow()` |
| `cmdHelp(args)` | `help` | Prints the complete command reference |
| `cmdExit()` | `exit` | Calls `cmdSave()` then sets `running_ = false` |

---

### 5.20 `main.cpp` — Entry Point

**Purpose**: Initialises all components and wires them together.

```cpp
int main() {
    SetConsoleOutputCP(65001);     // Line 24: Enable UTF-8 output on Windows console
    SetConsoleCP(65001);           // Line 25: Enable UTF-8 input on Windows console

    // Print startup banner (Lines 27-31)

    // Step 1: Initialize MongoDB (Lines 34-36)
    MongoConfig mongoConfig;
    mongoConfig.mongoURI = "mongodb://localhost:27017";
    MongoLogger mongoLogger(mongoConfig);   // Prints "MongoDB not available" if drivers missing

    // Step 2: Initialize core components (Lines 39-45)
    FirewallStats  stats;
    stats.startTime = Packet::currentTimestamp();
    FileLogger     logger("firewall.log", "rules.conf");
    Stack          history(100);         // 100-entry circular history
    Queue          packetQueue(1000);    // 1000-packet buffer
    TrafficMonitor monitor(100, 20, 10); // SYN=100, PortScan=20, Window=10s
    RuleEngine     engine;

    // Step 3: Load persisted config from rules.conf (Lines 48-67)
    // Loads rules, blacklist IPs, whitelist IPs, default policy

    // Step 4: Create PacketProcessor (Line 70)
    PacketProcessor processor(engine, monitor, logger, mongoLogger, history, packetQueue, stats);

    // Step 5: Create AdminCLI and start REPL (Lines 73-75)
    AdminCLI cli(engine, processor, stats, logger, history, monitor);
    cli.run();  // ← Blocks here until user types 'exit'

    // Step 6: Shutdown — save state to rules.conf (Lines 78-86)
}
```

---

## 🔧 6. All Functionalities Used in This Project

| # | Functionality | Class(es) | Purpose in This Project | Data Structure Used |
|---|---------------|-----------|-------------------------|---------------------|
| 1 | **Rule Matching** | `BST`, `RuleEngine` | Evaluates which firewall rule matches an incoming packet | Binary Search Tree keyed on priority |
| 2 | **IP Whitelisting** | `HashMap`, `RuleEngine` | Instant O(1) check if a source IP is trusted | HashMap with djb2 hash |
| 3 | **IP Blacklisting** | `HashMap`, `RuleEngine` | Instant O(1) check if a source IP is blocked | HashMap with djb2 hash |
| 4 | **Rule Storage** | `LinkedList`, `RuleEngine` | Maintains rules in sorted order for display/serialisation | Singly-Linked List |
| 5 | **Packet Buffering** | `Queue`, `PacketProcessor` | FIFO buffer for incoming packets before processing | Circular Array Queue |
| 6 | **History Tracking** | `Stack`, `PacketProcessor` | LIFO archive of the most recent processed packets | Circular Array Stack |
| 7 | **SYN Flood Detection** | `TrafficMonitor`, `HashMap` | Counts TCP SYN packets per source IP in a sliding window | HashMap (increment + threshold check) |
| 8 | **Port Scan Detection** | `TrafficMonitor`, `HashMap` | Counts distinct destination ports probed per source IP | Two HashMaps (presence flag + counter) |
| 9 | **CSV Logging** | `FileLogger` | Writes 10-field CSV log entries to `firewall.log` | File I/O with ofstream |
| 10 | **MongoDB Logging** | `MongoLogger` | Mirrors logs and rules to a MongoDB database | BSON documents via mongocxx driver |
| 11 | **Config Persistence** | `FileLogger` | Saves/loads rules, blacklist, whitelist to/from `rules.conf` | INI-style section parsing |
| 12 | **Log Querying** | `FileLogger`, `MongoLogger` | Search logs by IP, action, or time window | Sequential file scan / MongoDB find() |
| 13 | **Packet Validation** | `Packet` | Rejects packets with invalid IP format or port range | String parsing with lambdas |
| 14 | **Packet Simulation** | `PacketSimulator` | Generates test packets for debugging | Auto-increment ID + timestamp |
| 15 | **Admin CLI REPL** | `AdminCLI` | Interactive command shell with 21 commands | String tokenization + dispatch |
| 16 | **Enum Conversions** | `enums.cpp` | Converts between enum values and user-visible strings | Switch statements + string transforms |
| 17 | **Dynamic Rehashing** | `HashMap` | Automatically doubles hash table size when load > 0.75 | Rehash with new bucket array |
| 18 | **Graceful Degradation** | `MongoLogger` | Compiles without MongoDB drivers using stub functions | Preprocessor `#ifdef USE_MONGODB` |
| 19 | **Statistics Dashboard** | `FirewallStats` | Tracks and displays all runtime counters | Header-only struct with print() |
| 20 | **Tree Balancing Analysis** | `BST` | Reports tree height and balance status for DSA analysis | Recursive height + balance check |

---

## 🗄️ 7. MongoDB Backend — Complete Explanation

### What is MongoDB?
MongoDB is a **NoSQL document database** that stores data as flexible JSON-like documents (BSON). Unlike SQL databases with rigid tables, MongoDB collections can store documents with different shapes.

### Why MongoDB in this project?
1. **Schema flexibility**: Firewall logs, rules, and threat records have different fields — MongoDB handles this naturally without migrations.
2. **High-speed writes**: Log writing is on the hot path (every packet). MongoDB's write performance is excellent.
3. **Query capability**: Rich query language for filtering logs by IP, action, time range.
4. **DSA demonstration**: Shows how a backend persistence layer integrates with custom data structures.

### Connection Architecture
```
Your C++ Code
    │
    ├── #include <mongocxx/client.hpp>       ← C++ Driver API
    │       │
    │       ├── libmongocxx.dll              ← C++ driver shared library
    │       ├── libbsoncxx.dll               ← BSON C++ serialisation
    │       │       │
    │       │       ├── libmongoc2.dll        ← C driver (underlying implementation)
    │       │       ├── libbson2.dll           ← BSON C serialisation
    │       │       ├── libutf8proc.dll        ← UTF-8 string processing
    │       │       └── libz.dll              ← Zlib compression
    │       │
    │       └── Connects to → mongodb://localhost:27017
    │                              │
    │                              ▼
    │                     MongoDB Server (mongod)
    │                              │
    │                              ▼
    │                       Database: firewall_db
    │                              │
    │                    ┌─────────┼─────────────┐
    │                    │         │              │
    │                    ▼         ▼              ▼
    │              trafficlog   rules     blacklist/whitelist
    │               (events)  (config)      (IP lists)
    │                    │
    │                    ▼
    │                threats
    │            (security alerts)
```

### How the Graceful Degradation Works

In `CMakeLists.txt`:
```cmake
option(WITH_MONGODB "Compile with MongoDB drivers" OFF)   # Default is OFF
if (WITH_MONGODB)
    target_compile_definitions(Firewall PRIVATE USE_MONGODB)  # This defines the macro
```

In `MongoLogger.cpp`:
```cpp
#ifdef USE_MONGODB
    // === REAL IMPLEMENTATION (300 lines) ===
    // Full MongoDB driver integration, BSON document building, CRUD operations
#else
    // === STUB IMPLEMENTATION (25 lines) ===
    MongoLogger::MongoLogger(const MongoConfig& cfg) {
        cout << "[MongoLogger] MongoDB not available — using flat-file persistence.\n";
    }
    void MongoLogger::logEvent(...) {}      // Does nothing
    vector<string> MongoLogger::queryByIP(...) { return {}; }  // Returns empty
    // ... all other methods are empty stubs
#endif
```

### MongoDB CRUD Operations in This Project

| Operation | Method | MongoDB Action | When Used |
|-----------|--------|----------------|-----------|
| **Create** | `logEvent()` | `col.insert_one(doc)` on `trafficlog` | Every packet processed |
| **Create** | `logThreat()` | `col.insert_one(doc)` on `threats` | When SYN flood/port scan detected |
| **Create** | `saveRule()` | `col.insert_one(doc)` on `rules` | When admin adds a rule |
| **Create** | `saveBlacklistEntry()` | `col.insert_one(doc)` on `blacklist` | When admin blocks an IP |
| **Create** | `saveWhitelistEntry()` | `col.insert_one(doc)` on `whitelist` | When admin whitelists an IP |
| **Read** | `queryByIP()` | `col.find({"sourceIP": ip})` on `trafficlog` | `query --ip` command |
| **Read** | `queryByAction()` | `col.find({"action": action})` on `trafficlog` | `query --action` command |
| **Read** | `loadBlacklist()` | `col.find({})` on `blacklist` | On startup / `load` command |
| **Delete** | `deleteRule()` | `col.delete_one({"ruleID": id})` on `rules` | `del-rule` command |
| **Delete** | `deleteBlacklistEntry()` | `col.delete_one({"ip": ip})` on `blacklist` | `remove-block` command |

---

## 🎯 8. CLI Command Scenarios — Word-by-Word Breakdown

### Scenario 1: Adding a Rule to Block SSH

```
firewall> add-rule BLOCK INBOUND TCP 192.168.1.150 22 10 Block SSH access
```

| Position | Word | Meaning | Which function receives it |
|----------|------|---------|---------------------------|
| 0 | `add-rule` | Command keyword | `dispatch()` routes to `cmdAddRule()` |
| 1 | `BLOCK` | Action enum → `Action::BLOCK` | `args[0]` → `strToAction("BLOCK")` |
| 2 | `INBOUND` | Direction enum → `Direction::INBOUND` | `args[1]` → `strToDirection("INBOUND")` |
| 3 | `TCP` | Protocol enum → `Protocol::TCP` | `args[2]` → `strToProtocol("TCP")` |
| 4 | `192.168.1.150` | Source IP to filter | `args[3]` → validated by `validateIP()`, stored as `r.sourceIP` |
| 5 | `22` | Destination port (SSH) | `args[4]` → validated by `validatePort()`, parsed via `stoi()`, stored as `r.destPort` |
| 6 | `10` | Priority (lower = higher precedence) | `args[5]` → parsed via `stoi()`, stored as `r.priority` |
| 7-8 | `Block SSH access` | Description string | `args[6..n]` → concatenated into `r.description` |

**Execution chain**:
1. `AdminCLI::cmdAddRule()` creates a `Rule` object with these fields
2. Calls `engine_.addRule(r)` → `RuleEngine::addRule()` 
3. `RuleEngine` assigns `ruleID = nextRuleID_++`
4. Inserts into `ruleList_` (LinkedList) via `insertSorted()` — O(n)
5. Calls `rebuildBST()` — clears BST, re-inserts all enabled rules — O(n log n)
6. Prints confirmation: `"Rule added successfully with ID: 1"`

---

### Scenario 2: Blacklisting an IP

```
firewall> block-ip 192.168.1.99
```

| Position | Word | Meaning | Function |
|----------|------|---------|----------|
| 0 | `block-ip` | Command keyword | Routes to `cmdBlockIP()` |
| 1 | `192.168.1.99` | IP to block | Validated, then `engine_.addToBlacklist("192.168.1.99")` |

**Execution chain**:
1. `AdminCLI::cmdBlockIP()` validates the IP format
2. Calls `engine_.addToBlacklist(ip)` → `RuleEngine::addToBlacklist()`
3. `blacklist_.insert("192.168.1.99", 1)` → `HashMap::insert()`
4. djb2 hashes the IP string → computes bucket index
5. Appends `{"192.168.1.99", 1}` to that bucket's chain
6. Future packets from this IP hit `blacklist_.contains()` → O(1) → instant BLOCK

---

### Scenario 3: Whitelisting an IP

```
firewall> allow-ip 10.0.0.5
```

Same flow as blacklisting but uses `whitelist_` HashMap. Whitelisted IPs are checked **before** blacklisted IPs in `RuleEngine::evaluate()`, so whitelist takes precedence.

---

### Scenario 4: Sending a Test Packet (Normal Traffic)

```
firewall> send-packet 192.168.1.50 80 TCP INBOUND
```

| Position | Word | Meaning |
|----------|------|---------|
| 0 | `send-packet` | Command keyword |
| 1 | `192.168.1.50` | Source IP of the simulated packet |
| 2 | `80` | Destination port (HTTP) |
| 3 | `TCP` | Protocol |
| 4 | `INBOUND` | Direction (optional, defaults to INBOUND) |

**Execution chain**:
1. `cmdSendPacket()` creates packet via `simulator_.createPacket()`
2. Prints: `"Injecting: [Pkt#1] 192.168.1.50 -> 10.0.0.1:80 TCP INBOUND @ ..."`
3. Calls `processor_.process(p)` → `PacketProcessor::process()`
4. Validates packet → enqueues → dequeues → threat check → whitelist check → blacklist check → BST rule match → default policy → logs → pushes to history

---

### Scenario 5: Simulating a SYN Flood Attack

```
firewall> send-packet 10.0.0.99 443 TCP INBOUND SYN
```

| Position | Word | Meaning |
|----------|------|---------|
| 5 | `SYN` | This is a TCP SYN handshake packet (`isSYN = true`) |

If you run this command **101 times** within 10 seconds (the default window), the `TrafficMonitor` will detect a SYN flood:
1. Each call increments `synCounters_["10.0.0.99"]` via the HashMap
2. On the 101st packet, the counter exceeds `synThreshold_ (100)`
3. Returns `ThreatType::SYN_FLOOD`
4. `PacketProcessor` auto-blacklists `10.0.0.99`
5. All future packets from this IP are instantly blocked at O(1)

---

### Scenario 6: Viewing Traffic Statistics

```
firewall> show-stats
```

Prints:
```
┌──────────────────────────────────────────────┐
│        FIREWALL STATISTICS SUMMARY           │
├──────────────────────────────────────────────┤
│  Start Time         : 2026-06-11T21:00:00Z   │
│  Total Processed    : 15                      │
│  Total Allowed      : 8                       │
│  Total Blocked      : 7                       │
│  Total Logged       : 15                      │
│  SYN Floods Blocked : 1                       │
│  Port Scans Blocked : 0                       │
│  Buffer Overflows   : 0                       │
└──────────────────────────────────────────────┘
  Active Blacklist Size: 2
  Active Whitelist Size: 1
```

---

### Scenario 7: Querying Firewall Logs

```
firewall> query --ip 192.168.1.50
```

| Position | Word | Meaning |
|----------|------|---------|
| 0 | `query` | Command keyword |
| 1 | `--ip` | Query type: filter by source IP |
| 2 | `192.168.1.50` | The IP to search for |

**Execution**: Opens `firewall.log`, reads each CSV line, splits by comma, checks if field[2] (sourceIP) matches `192.168.1.50`, returns matching lines.

Other query modes:
- `query --action BLOCK` → finds all blocked packets
- `query --last 5` → finds all logs from the last 5 minutes

---

## 🎨 9. Why No GUI? + Proposed GUI Design

### Why the Project Doesn't Have a GUI

1. **DSA Focus**: This is a Data Structures & Algorithms major project. The assessment criteria prioritize algorithmic implementation (custom BST, HashMap, LinkedList, Stack, Queue) over visual design.
2. **C++ GUI Complexity**: Building GUIs in C++ requires heavyweight frameworks (Qt, wxWidgets, Dear ImGui) that add thousands of lines of boilerplate code, external dependencies, and platform-specific complications — distracting from the core DSA demonstration.
3. **Terminal is Authentic**: Real-world firewalls (iptables, pf, Windows Firewall netsh) are primarily CLI-based. The terminal interface mirrors professional tooling.
4. **Rapid Development**: CLI development is 5-10x faster than GUI development, allowing more time to be spent on algorithmic correctness and edge cases.

### If a GUI Were Required — Proposed Design

Here is a mockup of what a professional GUI dashboard for this firewall would look like:

![Proposed Firewall GUI Dashboard — Dark mode with stat cards, packet throughput chart, and live traffic table](C:/Users/Cyber World/.gemini/antigravity/brain/ed25d665-cb28-4820-97d6-55bf9004bd7c/firewall_gui_mockup_1781194447625.png)

#### GUI Layout Breakdown:
- **Left Sidebar**: Navigation panel with icons for Dashboard, Rules, Blacklist/Whitelist, Traffic Monitor, Threat Alerts, Logs, and Settings
- **Top Stats Row**: Four metric cards showing Total Processed (cyan), Allowed (green), Blocked (red), and Threats Detected (amber)
- **Center Chart**: Real-time line graph showing packet throughput over time — blue line for allowed traffic, red line for blocked
- **Bottom Table**: Live scrolling data table showing recent packets with colour-coded action badges (green ALLOW / red BLOCK)
- **Top Bar**: Application title and a "System Online" status indicator

#### How It Could Be Built:
- **Dear ImGui** (C++): Lightweight immediate-mode GUI library. Best for developer tools and dashboards. Renders via OpenGL/DirectX.
- **Qt Framework** (C++): Full-featured cross-platform GUI toolkit. Supports rich widgets, charts, styling with QSS (CSS-like).
- **Electron + WebSocket Bridge** (HTML/JS frontend, C++ backend): The C++ firewall runs as a backend server exposing a WebSocket API. A web-based dashboard (React/Vue) connects and displays data in real-time.

---

## 🚀 10. Compilation & Running Instructions

### Option A: Building with CMake (Recommended)

```powershell
# Step 1: Navigate to project directory
cd "C:\Users\Cyber World\Desktop\DSA\Terminal"

# Step 2: Create and enter build directory
mkdir build
cd build

# Step 3a: Configure WITHOUT MongoDB (default)
cmake ..

# Step 3b: OR configure WITH MongoDB (if drivers are installed)
cmake -DWITH_MONGODB=ON ..

# Step 4: Compile
cmake --build . --config Release

# Step 5: Run the firewall
./Firewall.exe
```

### Option B: Direct Compilation with G++

```powershell
g++ -std=c++17 src/*.cpp -Iinclude -o Firewall.exe
./Firewall.exe
```

### Option C: Building from VS Code
1. Open the project folder in VS Code
2. Press `Ctrl+Shift+B` to run the build task
3. Press `F5` to launch with debugger attached

---

## ❓ 11. Frequently Asked Questions

**Q: Why use a BST instead of just searching the LinkedList for rule matching?**
A: LinkedList matching is O(n) — every packet checks every rule. BST matching is O(log n) on average, which is significantly faster when you have many rules and high packet volumes.

**Q: Why use separate chaining instead of open addressing in the HashMap?**
A: Separate chaining with rehashing maintains robust O(1) lookups even under clustered IP segments (like 192.168.1.x). Open addressing suffers from collision cascading where clusters of nearby IPs create long probe sequences.

**Q: Why circular arrays for Stack and Queue instead of linked lists?**
A: Circular buffers avoid continuous dynamic memory allocation/deallocation, eliminating memory fragmentation and guaranteeing O(1) push/pop with zero heap overhead.

**Q: What do the matched rule ID codes mean?**

| Code | Meaning |
|------|---------|
| -1 | Packet allowed because source IP is **whitelisted** |
| -2 | Packet blocked because source IP is **blacklisted** |
| -3 | No rule matched — **default policy** was applied |
| -4 | Packet blocked because it had **invalid format** (bad IP or port) |
| -5 | Packet blocked because the **queue buffer overflowed** |
| 1+ | The actual `ruleID` of the rule that matched |

**Q: Does this project work without MongoDB installed?**
A: Yes! By default, MongoDB is disabled. The `MongoLogger` uses stub functions that print a warning and do nothing. All logging falls back to CSV flat-file persistence automatically.

---

> **Have more questions?** Feel free to ask — I'm right here to help you understand every line of this project! 🚀
