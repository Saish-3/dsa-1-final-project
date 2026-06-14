// ============================================================
//  ThreatWatch - A mini SIEM (Security Monitoring) System
//  Demonstrates 8 core Data Structures in C++
//  Compile:  g++ -std=c++17 threatwatch.cpp -o threatwatch
//  Run:      ./threatwatch
// ============================================================

#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>   // Threat List
#include <unordered_map>   // Device Lookup
#include <stack>           // Login History
#include <queue>           // Alert Line + Danger Sorter + Data Balancer
#include <algorithm>
using namespace std;

// ------------------------------------------------------------
// 1. THREAT LIST  ->  Hash Set (O(1) keyword lookup)
// ------------------------------------------------------------
class ThreatList {
    unordered_set<string> threats;
public:
    void add(const string& keyword) { threats.insert(keyword); }

    // scan a log line for any known threat keyword
    void scan(const string& log) {
        bool found = false;
        for (const string& t : threats) {
            if (log.find(t) != string::npos) {
                cout << "  [!] THREAT DETECTED: \"" << t << "\" in log\n";
                found = true;
            }
        }
        if (!found) cout << "  [ok] log is clean\n";
    }
};

// ------------------------------------------------------------
// 2. LOGIN HISTORY  ->  Stack (step back through session)
// ------------------------------------------------------------
class LoginHistory {
    stack<string> steps;
public:
    void doAction(const string& action) {
        steps.push(action);
        cout << "  step recorded: " << action << "\n";
    }
    void stepBack() {
        if (steps.empty()) { cout << "  no steps to trace back\n"; return; }
        cout << "  stepping back from: " << steps.top() << "\n";
        steps.pop();
    }
};

// ------------------------------------------------------------
// 3. ALERT LINE  ->  Queue (FIFO buffering)
// ------------------------------------------------------------
class AlertLine {
    queue<string> alerts;
public:
    void receive(const string& alert) {
        alerts.push(alert);
        cout << "  buffered: " << alert << "\n";
    }
    void process() {
        if (alerts.empty()) { cout << "  queue empty\n"; return; }
        cout << "  processing (FIFO): " << alerts.front() << "\n";
        alerts.pop();
    }
};

// ------------------------------------------------------------
// 4. DEVICE LOOKUP  ->  Hash Map (ID -> device info, O(1))
//real world application- to search ip addresss,mac address , device id.
// ------------------------------------------------------------
class DeviceLookup {
    unordered_map<string, string> devices;  // id -> info
public:
    void add(const string& id, const string& info) { devices[id] = info; }
    void find(const string& id) {
        auto it = devices.find(id);
        if (it != devices.end()) cout << "  found: " << id << " -> " << it->second << "\n";
        else cout << "  device " << id << " not found\n";
    }
};

// ------------------------------------------------------------
// 5. DANGER SORTER  ->  Priority Queue / Max-Heap (by severity)
// ------------------------------------------------------------
struct Alert {
    int severity;        // higher = more critical
    string message;
    bool operator<(const Alert& o) const { return severity < o.severity; }
};
class DangerSorter {
    priority_queue<Alert> pq;  // max-heap
public:
    void add(int severity, const string& msg) {
        pq.push({severity, msg});
        cout << "  added (sev " << severity << "): " << msg << "\n";
    }
    void handleMostCritical() {
        if (pq.empty()) { cout << "  no alerts\n"; return; }
        Alert a = pq.top(); pq.pop();
        cout << "  handling MOST CRITICAL (sev " << a.severity << "): " << a.message << "\n";
    }
};

// ------------------------------------------------------------
// 6 & 7. NETWORK MAP + EVENT TRACER
//        -> Graph (adjacency list) + BFS (shortest path)
// ------------------------------------------------------------
class Network {
    unordered_map<string, vector<string>> adj;  // server -> neighbours
public:
    void link(const string& a, const string& b) {
        adj[a].push_back(b);
        adj[b].push_back(a);   // undirected link
    }
    void showMap() {
        for (auto& p : adj) {
            cout << "  " << p.first << " <-> ";
            for (auto& n : p.second) cout << n << " ";
            cout << "\n";
        }
    }
    // BFS: fastest (fewest hops) path from src to dst
    void tracePath(const string& src, const string& dst) {
        if (!adj.count(src) || !adj.count(dst)) { cout << "  unknown server\n"; return; }
        unordered_map<string, string> parent;
        unordered_set<string> visited;
        queue<string> q;
        q.push(src); visited.insert(src); parent[src] = "";

        while (!q.empty()) {
            string cur = q.front(); q.pop();
            if (cur == dst) break;
            for (auto& nb : adj[cur]) {
                if (!visited.count(nb)) {
                    visited.insert(nb);
                    parent[nb] = cur;
                    q.push(nb);
                }
            }
        }
        if (!visited.count(dst)) { cout << "  no path found\n"; return; }

        // rebuild path
        vector<string> path;
        for (string at = dst; at != ""; at = parent[at]) path.push_back(at);
        reverse(path.begin(), path.end());

        cout << "  fastest trace: ";
        for (size_t i = 0; i < path.size(); ++i)
            cout << path[i] << (i + 1 < path.size() ? " -> " : "\n");
    }
};

// ------------------------------------------------------------
// 8. DATA BALANCER  ->  Min-Heap (assign work to least-busy server)
// ------------------------------------------------------------
struct Server {
    int load;
    string name;
    bool operator>(const Server& o) const { return load > o.load; }
};
class DataBalancer {
    priority_queue<Server, vector<Server>, greater<Server>> pq;  // min-heap
public:
    void addServer(const string& name) {
        pq.push({0, name});
        cout << "  registered server: " << name << "\n";
    }
    void assignJob() {
        if (pq.empty()) { cout << "  no servers\n"; return; }
        Server s = pq.top(); pq.pop();
        cout << "  job -> " << s.name << " (load was " << s.load << ")\n";
        s.load++;                  // server now busier
        pq.push(s);
    }
};

// ------------------------------------------------------------
//  MENU
// ------------------------------------------------------------
int main() {
    ThreatList   threats;
    LoginHistory history;
    AlertLine    alertLine;
    DeviceLookup devices;
    DangerSorter sorter;
    Network      net;
    DataBalancer balancer;

    // --- seed some demo data ---
    threats.add("sql injection");
    threats.add("brute force");
    threats.add("malware");

    devices.add("DEV-101", "Finance-PC (192.168.1.10)");
    devices.add("DEV-102", "HR-Laptop (192.168.1.11)");

    net.link("Web", "App");
    net.link("App", "DB");
    net.link("Web", "Firewall");
    net.link("DB", "Backup");

    balancer.addServer("Node-A");
    balancer.addServer("Node-B");
    balancer.addServer("Node-C");

    int choice;
    do {
        cout << "\n===== ThreatWatch SIEM =====\n"
             << "1. Threat List   - scan a log\n"
             << "2. Login History - add step / step back\n"
             << "3. Alert Line    - buffer / process (FIFO)\n"
             << "4. Device Lookup - find device by ID\n"
             << "5. Danger Sorter - add / handle by severity\n"
             << "6. Network Map   - show server links\n"
             << "7. Event Tracer  - fastest path between servers\n"
             << "8. Data Balancer - assign analysis job\n"
             << "0. Exit\n"
             << "Choice: ";
        if (!(cin >> choice)) break;
        cin.ignore();
        string s, a, b;

        switch (choice) {
            case 1:
                cout << "Enter log line: "; getline(cin, s);
                threats.scan(s);
                break;
            case 2:
                cout << "1=add step  2=step back: "; { int x; cin >> x; cin.ignore();
                    if (x == 1) { cout << "Action: "; getline(cin, s); history.doAction(s); }
                    else history.stepBack(); }
                break;
            case 3:
                cout << "1=receive alert  2=process: "; { int x; cin >> x; cin.ignore();
                    if (x == 1) { cout << "Alert: "; getline(cin, s); alertLine.receive(s); }
                    else alertLine.process(); }
                break;
            case 4:
                cout << "Device ID: "; getline(cin, s); devices.find(s);
                break;
            case 5:
                cout << "1=add alert  2=handle critical: "; { int x; cin >> x; cin.ignore();
                    if (x == 1) { int sev; cout << "Severity: "; cin >> sev; cin.ignore();
                                  cout << "Message: "; getline(cin, s); sorter.add(sev, s); }
                    else sorter.handleMostCritical(); }
                break;
            case 6:
                net.showMap();
                break;
            case 7:
                cout << "From: "; getline(cin, a);
                cout << "To: ";   getline(cin, b);
                net.tracePath(a, b);
                break;
            case 8:
                balancer.assignJob();
                break;
            case 0:
                cout << "Bye.\n";
                break;
            default:
                cout << "Invalid choice.\n";
        }
    } while (choice != 0);

    return 0;
}
