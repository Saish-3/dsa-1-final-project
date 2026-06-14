╔════════════════════════════════════════════════════════════════════════════╗
║                          THREATWATCH - SIEM SYSTEM                        ║
║              A Console-Based Security Monitoring Platform in C++            ║
╚════════════════════════════════════════════════════════════════════════════╝


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PROJECT OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ThreatWatch is a console-based SIEM (Security Information and Event Management)
prototype written entirely in C++. It solves eight operational problems of
security monitoring platforms—each using the optimal data structure for the task.

✓ Pure C++ using only the standard library (STL)
✓ No external dependencies, GUI, or database
✓ Single-file implementation (~300 lines)
✓ Interactive menu-driven interface
✓ Pre-loaded with demo data for immediate testing


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PROBLEM STATEMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Modern security systems must process thousands of activity logs per second.
ThreatWatch addresses these 8 critical operational challenges:

  1. SLOW KEYWORD SCANNING
     Problem: Scanning logs against attack patterns using a simple list is O(n)
     per log — unscalable for high-volume environments.
     Solution: Hash Set for O(1) lookup

  2. NO SESSION TRACING
     Problem: When a user's session is compromised, there's no efficient way to
     reconstruct backwards through their activity sequence.
     Solution: Stack (LIFO) for step-by-step session replay

  3. UNORDERED ALERT HANDLING
     Problem: Alerts arrive in massive volumes and are processed randomly,
     leaving critical breaches waiting behind routine alerts.
     Solution: Queue (FIFO) for fair, sequential processing

  4. SLOW DEVICE LOOKUP
     Problem: Finding a device by ID in an unsorted list requires linear search.
     Solution: Hash Map for O(1) device identification

  5. NO SEVERITY PRIORITIZATION
     Problem: All alerts treated equally regardless of danger level.
     Solution: Max-Heap (Priority Queue) to handle critical threats first

  6. NO NETWORK TOPOLOGY
     Problem: Without a map of server links, tracing lateral movement is
     manual guesswork.
     Solution: Graph (Adjacency List) for network representation

  7. NO AUTOMATED ATTACK TRACING
     Problem: Finding the fastest path from detection point to attack origin
     requires human analysis.
     Solution: BFS algorithm on graph for shortest-path detection

  8. UNBALANCED LOAD
     Problem: Analysis work isn't distributed, creating bottlenecks while
     other servers sit idle.
     Solution: Min-Heap (Priority Queue) for intelligent load balancing


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PROJECT FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📄 threatwatch.cpp                  Main implementation (single file, ~300 lines)
  📄 ThreatWatch_Justification.docx   Design rationale & real SIEM tool mapping
  📄 README.txt                       This file
  📁 Screenshots/                     Demonstration screenshots


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SYSTEM REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • C++ compiler supporting C++17 or later (g++ 7+, clang, MSVC)
  • Supports: Linux, macOS, Windows (MinGW/WSL/MSVC)
  • No external libraries required (uses only C++ STL)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  COMPILE:
  ────────
    Linux / macOS:
      $ g++ -std=c++17 threatwatch.cpp -o threatwatch

    Windows (MinGW):
      $ g++ -std=c++17 threatwatch.cpp -o threatwatch.exe

  RUN:
  ────
    Linux / macOS:
      $ ./threatwatch

    Windows:
      $ threatwatch.exe

  DEMO DATA:
  ──────────
  The program launches with pre-loaded data:
    • Threat keywords: "sql injection", "brute force", "malware"
    • Devices: DEV-101 (Finance-PC), DEV-102 (HR-Laptop)
    • Network: 5 servers (Web, App, DB, Firewall, Backup)
    • Load balancers: 3 nodes (Node-A, Node-B, Node-C)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 8 CORE FEATURES & DATA STRUCTURES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 1. THREAT LIST (Hash Set)                                               │
  │    Fast keyword scanning of incoming log lines                          │
  │    Time Complexity: O(1) lookup                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 2. LOGIN HISTORY (Stack - LIFO)                                         │
  │    Step backwards through user session activity for forensics           │
  │    Time Complexity: O(1) push/pop                                       │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 3. ALERT LINE (Queue - FIFO)                                            │
  │    Buffer incoming alerts in strict arrival order                       │
  │    Time Complexity: O(1) enqueue/dequeue                                │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 4. DEVICE LOOKUP (Hash Map)                                             │
  │    Find device info instantly by unique ID (IP, MAC, hostname)          │
  │    Time Complexity: O(1) lookup                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 5. DANGER SORTER (Priority Queue - Max Heap)                            │
  │    Always handle the most critical/dangerous alert first                │
  │    Time Complexity: O(log n) insertion/deletion                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 6. NETWORK MAP (Graph - Adjacency List)                                 │
  │    Visualize how servers are connected in the network topology          │
  │    Space: O(V + E) for V vertices, E edges                              │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 7. EVENT TRACER (BFS Algorithm on Graph)                                │
  │    Find the fastest path from detection point to attack origin          │
  │    Time Complexity: O(V + E) breadth-first search                       │
  └─────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 8. DATA BALANCER (Priority Queue - Min Heap)                            │
  │    Distribute security analysis jobs to least-loaded server             │
  │    Time Complexity: O(log n) insertion/deletion                         │
  └─────────────────────────────────────────────────────────────────────────┘


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 INTERACTIVE MENU
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The program displays a numbered menu (0-8) on startup. Enter a number and press
Enter. Some options have sub-menus (e.g., "1=add threat, 2=remove threat").


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 GUIDED DEMO WALKTHROUGH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Follow these steps to exercise all 8 features:

  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 1: THREAT LIST (Hash Set)                                       ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 1
  Input: "user attempted sql injection on login form"
  Expected Output: [!] THREAT DETECTED: "sql injection" in log

  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 2: THREAT LIST - CLEAN LOG                                      ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 1
  Input: "user opened dashboard"
  Expected Output: [ok] log is clean


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 3: LOGIN HISTORY (Stack - LIFO)                                 ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 2 → Sub-choice: 1
  Action: "viewed reports"
  Expected Output: step recorded: viewed reports

  Option: 2 → Sub-choice: 1
  Action: "downloaded file"
  Expected Output: step recorded: downloaded file

  Option: 2 → Sub-choice: 2
  Expected Output: stepping back from: downloaded file (LIFO - last in, first out!)


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 4: ALERT LINE (Queue - FIFO)                                    ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 3 → Sub-choice: 1
  Alert: "failed login"
  Expected Output: buffered: failed login

  Option: 3 → Sub-choice: 1
  Alert: "port scan"
  Expected Output: buffered: port scan

  Option: 3 → Sub-choice: 2
  Expected Output: processing (FIFO): failed login (first one processed first!)


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 5: DEVICE LOOKUP (Hash Map)                                     ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 4
  Device ID: "DEV-101"
  Expected Output: found: DEV-101 -> Finance-PC (192.168.1.10)

  Option: 4
  Device ID: "DEV-999"
  Expected Output: device DEV-999 not found (graceful miss)


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 6: DANGER SORTER (Priority Queue - Max Heap)                    ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 5 → Sub-choice: 1, Severity: 3, Message: "minor warning"
  Expected Output: added (sev 3): minor warning

  Option: 5 → Sub-choice: 1, Severity: 9, Message: "ransomware detected"
  Expected Output: added (sev 9): ransomware detected

  Option: 5 → Sub-choice: 1, Severity: 5, Message: "suspicious login"
  Expected Output: added (sev 5): suspicious login

  Option: 5 → Sub-choice: 2
  Expected Output: handling MOST CRITICAL (sev 9): ransomware detected
                   (Highest severity = first to be handled!)


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 7: NETWORK MAP (Graph - Adjacency List)                         ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 6
  Expected Output:
    Web <-> App Firewall
    App <-> Web DB
    DB <-> App Backup
    Firewall <-> Web
    Backup <-> DB


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 8: EVENT TRACER (BFS - Shortest Path)                           ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 7
  From: "Web"
  To: "Backup"
  Expected Output: fastest trace: Web -> App -> DB -> Backup


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ TEST 9: DATA BALANCER (Priority Queue - Min Heap)                    ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 8 (run this 4-5 times)
  Expected Output (round-robin to least-loaded):
    job -> Node-A (load was 0)
    job -> Node-B (load was 0)
    job -> Node-C (load was 0)
    job -> Node-A (load was 1)    ← Cycles back to least-loaded node
    (and so on...)


  ╔═══════════════════════════════════════════════════════════════════════╗
  ║ EXIT                                                                   ║
  ╚═══════════════════════════════════════════════════════════════════════╝
  Option: 0
  Expected Output: Bye.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PRE-LOADED DEMO DATA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The system launches with the following test data:

  THREAT KEYWORDS:
    ► "sql injection"
    ► "brute force"
    ► "malware"

  REGISTERED DEVICES:
    ► DEV-101  Finance-PC (192.168.1.10)
    ► DEV-102  HR-Laptop (192.168.1.11)

  NETWORK TOPOLOGY:
    ► Web ↔ App
    ► App ↔ DB
    ► Web ↔ Firewall
    ► DB ↔ Backup

  LOAD BALANCER NODES:
    ► Node-A
    ► Node-B
    ► Node-C


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 TECHNICAL NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ► BFS for Event Tracer:
    The network is UNWEIGHTED, so BFS guarantees the fewest-hops path is the
    shortest path. If network links carried a cost (latency, trust score),
    Dijkstra's algorithm would replace BFS without changing the graph structure.

  ► Real-World SIEM Mapping:
    Each ThreatWatch component maps to production SIEM tools:
      • Threat List           → Splunk/Elastic pattern matching
      • Login History         → Audit log reversal / forensics
      • Alert Line            → Message queuing (Kafka, RabbitMQ)
      • Device Lookup         → Asset inventory databases
      • Danger Sorter         → Alert triage & escalation
      • Network Map           → Network topology discovery
      • Event Tracer          → Lateral movement detection
      • Data Balancer         → Distributed log analysis (Elasticsearch nodes)

    See ThreatWatch_Justification.docx for detailed mapping.

  ► Memory Model:
    All data lives in memory (no persistence). Program state resets on exit.
    This is intentional for a prototype; production systems use persistent stores.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CODE STRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The ~300-line implementation is organized as follows:

  ► Includes & Namespace
  ► 8 Class Definitions (one per data structure)
  ► Helper Structs (Alert, Server)
  ► main() function with menu loop
  ► Standard input/output only (no external I/O)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 LEARNING OUTCOMES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

By studying and interacting with ThreatWatch, you will understand:

  ✓ When to use Hash Sets for O(1) lookup
  ✓ When Stack LIFO semantics solve audit/undo problems
  ✓ When Queue FIFO semantics ensure fairness
  ✓ When Hash Maps provide instant key-value lookup
  ✓ How Priority Queues (heaps) implement custom sorting
  ✓ Graph representations (adjacency lists) for networks
  ✓ BFS algorithm for shortest-path detection
  ✓ Load balancing strategies using data structures
  ✓ How to apply DSA concepts to real security problems


╔════════════════════════════════════════════════════════════════════════════╗
║                 Questions? See ThreatWatch_Justification.docx              ║
║                    For more details on architecture & design               ║
╚════════════════════════════════════════════════════════════════════════════╝