============================================================
 ThreatWatch - A Mini SIEM System in C++
 Data Structures & Algorithms Project
============================================================

WHAT IT IS
----------
ThreatWatch is a console-based Security Information and Event
Management (SIEM) prototype written entirely in C++. It solves
eight operational problems of a security monitoring platform,
each using the data structure best suited to the task.

It uses ONLY the C++ standard library (STL) - no external
dependencies, no GUI, no database.


FILES IN THIS SUBMISSION
------------------------
  threatwatch.cpp               - the full implementation (single file)
  ThreatWatch_Justification.docx - design rationale + SIEM tool mapping
  README.txt                    - this file
  Screenshots                   -  Screenshots demonstrating program execution


REQUIREMENTS
------------
  - A C++ compiler supporting C++17 (g++ 7+ or clang)
  - Works on Linux, macOS, or Windows (MinGW / WSL / MSVC)


HOW TO COMPILE
--------------
  Linux / macOS:
      g++ -std=c++17 threatwatch.cpp -o threatwatch

  Windows (MinGW):
      g++ -std=c++17 threatwatch.cpp -o threatwatch.exe


HOW TO RUN
----------
  Linux / macOS:
      ./threatwatch

  Windows:
      threatwatch.exe

The program starts with demo data already loaded (threat
keywords, two devices, a 5-server network, and three balancer
nodes), so every feature can be demonstrated immediately.


THE 8 FEATURES (and their data structures)
------------------------------------------
  1. Threat List    - Hash Set        : instant keyword scanning of logs
  2. Login History  - Stack (LIFO)     : step back through session activity
  3. Alert Line     - Queue (FIFO)     : buffer alerts in arrival order
  4. Device Lookup  - Hash Map         : find a device by unique ID
  5. Danger Sorter  - Max-Heap         : handle most severe alert first
  6. Network Map    - Graph (adj list) : show how servers are linked
  7. Event Tracer   - BFS on the graph : fastest path back to source
  8. Data Balancer  - Min-Heap         : assign work to least-busy server


MENU GUIDE
----------
On launch you see a numbered menu (0-8). Type a number and press
Enter. Some options ask a follow-up (e.g. "1=add  2=process").


DEMO WALKTHROUGH (recommended for evaluation)
---------------------------------------------
Run the program and enter the following to exercise all 8 features:

  Option 1  (Threat List)
     -> type:  user attempted sql injection on login form
     Expected: THREAT DETECTED: "sql injection"

  Option 1  (clean log test)
     -> type:  user opened dashboard
     Expected: log is clean

  Option 2  (Login History) -> choose 1, action: "viewed reports"
  Option 2  (Login History) -> choose 1, action: "downloaded file"
  Option 2  (Login History) -> choose 2
     Expected: stepping back from: downloaded file   (LIFO order)

  Option 3  (Alert Line) -> choose 1, alert: "failed login"
  Option 3  (Alert Line) -> choose 1, alert: "port scan"
  Option 3  (Alert Line) -> choose 2
     Expected: processing (FIFO): failed login       (FIFO order)

  Option 4  (Device Lookup) -> ID: DEV-101
     Expected: found: DEV-101 -> Finance-PC (192.168.1.10)
  Option 4  (Device Lookup) -> ID: DEV-999
     Expected: device DEV-999 not found

  Option 5  (Danger Sorter) -> 1, severity 3, msg "minor warning"
  Option 5  (Danger Sorter) -> 1, severity 9, msg "ransomware detected"
  Option 5  (Danger Sorter) -> 1, severity 5, msg "suspicious login"
  Option 5  (Danger Sorter) -> 2
     Expected: handling MOST CRITICAL (sev 9): ransomware detected

  Option 6  (Network Map)
     Expected: prints all server links (Web, App, DB, Firewall, Backup)

  Option 7  (Event Tracer) -> From: Web   To: Backup
     Expected: fastest trace: Web -> App -> DB -> Backup

  Option 8  (Data Balancer)  [run 3-4 times]
     Expected: jobs distributed to least-loaded node each time
               (Node-A, then Node-B, then Node-C, then Node-A ...)

  Option 0  -> Exit


PRE-LOADED DEMO DATA
--------------------
  Threat keywords : "sql injection", "brute force", "malware"
  Devices         : DEV-101 (Finance-PC), DEV-102 (HR-Laptop)
  Network links   : Web<->App, App<->DB, Web<->Firewall, DB<->Backup
  Balancer nodes  : Node-A, Node-B, Node-C


NOTES FOR EVALUATION
--------------------
  - Event Tracer uses BFS because the network is UNWEIGHTED, so the
    fewest-hops path is the shortest path. If links carried a cost
    (latency / trust), Dijkstra's algorithm would replace BFS without
    changing the underlying graph.
  - All structures map to real SIEM mechanisms (Splunk / Elastic
    Security); see ThreatWatch_Justification.docx, Section 4.

============================================================