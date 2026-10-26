// CyberTrace - Mini Incident-Response Investigation Tool (single-file version)
// Build: g++ -std=c++11 -Wall -pthread -o cybertrace main.cpp
// On first run the three sample logs are written next to the program.


#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <list>
#include <stdexcept>
#include <thread>
#include <chrono>
using namespace std;

// ---------------------------------------------------------------
// Event: one log entry (ID, timestamp, IP address, event type)
// ---------------------------------------------------------------
class Event {
private:
    int eventID;
    string timestamp;
    string ipAddress;
    string eventType;

public:
    Event() : eventID(0) {}
    Event(int id, const string& time, const string& ip, const string& type)
        : eventID(id), timestamp(time), ipAddress(ip), eventType(type) {}

    int getEventID() const { return eventID; }
    string getTimestamp() const { return timestamp; }
    string getIPAddress() const { return ipAddress; }
    string getEventType() const { return eventType; }

    string toString() const {
        return "[" + to_string(eventID) + "] " + timestamp + " " + ipAddress + " " + eventType;
    }

    // Line format: eventID,timestamp,ipAddress,eventType
    static Event parseFromLine(const string& line) {
        stringstream ss(line);
        string idStr, time, ip, type;
        getline(ss, idStr, ',');
        getline(ss, time, ',');
        getline(ss, ip, ',');
        getline(ss, type, ',');
        int id = idStr.empty() ? 0 : stoi(idStr);
        return Event(id, time, ip, type);
    }
};

// ---------------------------------------------------------------
// EventList: singly linked list that keeps the timeline in order
// ---------------------------------------------------------------
struct EventNode {
    Event data;
    EventNode* next;
    EventNode(const Event& e) : data(e), next(nullptr) {}
};

class EventList {
private:
    EventNode* head;
    EventNode* tail;
    int count;

public:
    EventList() : head(nullptr), tail(nullptr), count(0) {}

    ~EventList() {
        EventNode* current = head;
        while (current) {
            EventNode* next = current->next;
            delete current;
            current = next;
        }
    }

    void insertEvent(const Event& e) {
        EventNode* node = new EventNode(e);
        if (!head) head = tail = node;
        else { tail->next = node; tail = node; }
        count++;
    }

    vector<Event> traverse() const {
        vector<Event> result;
        for (EventNode* cur = head; cur; cur = cur->next) result.push_back(cur->data);
        return result;
    }

    Event* findByID(int id) const {
        for (EventNode* cur = head; cur; cur = cur->next)
            if (cur->data.getEventID() == id) return &cur->data;
        return nullptr;
    }

    int size() const { return count; }
};

// ---------------------------------------------------------------
// HashTable: chained hash table (101 buckets) for ID / IP lookup
// ---------------------------------------------------------------
class HashTable {
private:
    static const int TABLE_SIZE = 101;
    vector<list<pair<string, Event> > > buckets;

    int hashKey(const string& key) const {
        unsigned long hash = 0;
        for (char c : key) hash = hash * 31 + static_cast<unsigned char>(c);
        return static_cast<int>(hash % TABLE_SIZE);
    }

public:
    HashTable() : buckets(TABLE_SIZE) {}

    void insert(const string& key, const Event& e) {
        buckets[hashKey(key)].push_back(make_pair(key, e));
    }

    vector<Event> find(const string& key) const {
        vector<Event> results;
        for (const auto& entry : buckets[hashKey(key)])
            if (entry.first == key) results.push_back(entry.second);
        return results;
    }

    bool remove(const string& key, int eventID) {
        auto& bucket = buckets[hashKey(key)];
        for (auto it = bucket.begin(); it != bucket.end(); ++it) {
            if (it->first == key && it->second.getEventID() == eventID) {
                bucket.erase(it);
                return true;
            }
        }
        return false;
    }
};

// ---------------------------------------------------------------
// ActionStack: stack of investigator actions (undo history)
// ---------------------------------------------------------------
struct Action {
    string type;
    string description;
    string timestamp;
};

class ActionStack {
private:
    vector<Action> actions;

public:
    void push(const Action& a) { actions.push_back(a); }

    Action pop() {
        if (actions.empty()) throw runtime_error("ActionStack is empty");
        Action top = actions.back();
        actions.pop_back();
        return top;
    }

    Action peek() const {
        if (actions.empty()) throw runtime_error("ActionStack is empty");
        return actions.back();
    }

    bool isEmpty() const { return actions.empty(); }
};

// ---------------------------------------------------------------
// RiskAnalyzer: attack-sequence detection and weighted risk score
// Pattern: FailedLogin -> SuccessfulLogin -> PrivilegeAccess -> FileTransfer
// ---------------------------------------------------------------
class RiskAnalyzer {
public:
    bool detectSuspiciousSequence(const vector<Event>& events) const {
        int stage = 0;
        for (const auto& e : events) {
            const string& type = e.getEventType();
            if (stage == 0 && type == "FailedLogin") stage = 1;
            else if (stage == 1 && type == "SuccessfulLogin") stage = 2;
            else if (stage == 2 && type == "PrivilegeAccess") stage = 3;
            else if (stage == 3 && type == "FileTransfer") return true;
        }
        return false;
    }

    int calculateRiskScore(const vector<Event>& events) const {
        int score = 0;
        for (const auto& e : events) {
            const string& type = e.getEventType();
            if (type == "FailedLogin") score += 1;
            else if (type == "SuccessfulLogin") score += 2;
            else if (type == "PrivilegeAccess") score += 5;
            else if (type == "FileTransfer") score += 7;
        }
        if (detectSuspiciousSequence(events)) score += 10;
        return score;
    }
};

// ---------------------------------------------------------------
// ReportGenerator: builds the investigation report text
// ---------------------------------------------------------------
class ReportGenerator {
public:
    string generateReport(const vector<Event>& timeline,
                          const vector<Event>& flaggedEvents,
                          int riskScore) const {
        stringstream report;
        report << "===== CyberTrace Investigation Report =====\n\n";
        report << "-- Timeline (" << timeline.size() << " events) --\n";
        for (const auto& e : timeline) report << "  " << e.toString() << "\n";

        report << "\n-- Flagged Suspicious Events --\n";
        if (flaggedEvents.empty()) report << "  None detected.\n";
        else for (const auto& e : flaggedEvents) report << "  " << e.toString() << "\n";

        report << "\n-- Risk Score: " << riskScore << " --\n";
        report << "============================================\n";
        return report.str();
    }
};

// ---------------------------------------------------------------
// LiveLogReader: returns only lines appended since the last poll
// ---------------------------------------------------------------
class LiveLogReader {
private:
    string filepath;
    ifstream logFile;
    streampos lastPosition;

public:
    explicit LiveLogReader(const string& path) : filepath(path), lastPosition(0) {
        logFile.open(filepath);
    }

    ~LiveLogReader() { if (logFile.is_open()) logFile.close(); }

    bool pollForNewEvents(vector<string>& newLines) {
        logFile.clear();
        logFile.seekg(lastPosition);
        string line;
        bool foundNew = false;
        while (getline(logFile, line)) {
            if (!line.empty()) { newLines.push_back(line); foundNew = true; }
        }
        logFile.clear();
        lastPosition = logFile.tellg();
        return foundNew;
    }
};

// ---------------------------------------------------------------
// Incident: owns the data structures for one investigation
// ---------------------------------------------------------------
class Incident {
private:
    string incidentID;
    EventList timeline;
    HashTable idIndex;
    HashTable ipIndex;
    RiskAnalyzer analyzer;
    ReportGenerator reporter;

public:
    explicit Incident(const string& id) : incidentID(id) {}

    void ingestLine(const string& line) {
        if (line.empty()) return;
        Event e = Event::parseFromLine(line);
        timeline.insertEvent(e);
        idIndex.insert(to_string(e.getEventID()), e);
        ipIndex.insert(e.getIPAddress(), e);
    }

    bool loadLogs(const string& filepath) {
        ifstream file(filepath);
        if (!file.is_open()) {
            cout << "Could not open log file: " << filepath << "\n";
            return false;
        }
        string line;
        int loaded = 0;
        while (getline(file, line)) {
            if (line.empty()) continue;
            ingestLine(line);
            loaded++;
        }
        cout << "Loaded " << loaded << " events from " << filepath << "\n";
        return true;
    }

    vector<Event> getTimeline() const { return timeline.traverse(); }
    vector<Event> searchByID(const string& id) const { return idIndex.find(id); }
    vector<Event> searchByIP(const string& ip) const { return ipIndex.find(ip); }

    int analyzeRisk(const string& ip) const { return analyzer.calculateRiskScore(ipIndex.find(ip)); }
    bool isSuspicious(const string& ip) const { return analyzer.detectSuspiciousSequence(ipIndex.find(ip)); }

    string generateFinalReport() const {
        vector<Event> all = timeline.traverse();

        vector<string> seenIPs;
        for (const auto& e : all) {
            bool found = false;
            for (const auto& ip : seenIPs) if (ip == e.getIPAddress()) { found = true; break; }
            if (!found) seenIPs.push_back(e.getIPAddress());
        }

        vector<Event> flagged;
        int totalRisk = 0;
        for (const auto& ip : seenIPs) {
            vector<Event> ipEvents = ipIndex.find(ip);
            if (analyzer.detectSuspiciousSequence(ipEvents)) {
                for (const auto& e : ipEvents) flagged.push_back(e);
                totalRisk += analyzer.calculateRiskScore(ipEvents);
            }
        }
        return reporter.generateReport(all, flagged, totalRisk);
    }

    string getIncidentID() const { return incidentID; }
};

// ---------------------------------------------------------------
// Investigator: the user; owns the undo history
// ---------------------------------------------------------------
class Investigator {
private:
    string name;
    ActionStack history;
    Incident* currentIncident;

public:
    explicit Investigator(const string& n) : name(n), currentIncident(nullptr) {}

    void assignIncident(Incident* incident) { currentIncident = incident; }

    void flagEvent(int eventID) {
        Action a;
        a.type = "FLAG_EVENT";
        a.description = "Flagged event " + to_string(eventID);
        history.push(a);
    }

    void deleteEvent(int eventID) {
        Action a;
        a.type = "DELETE_EVENT";
        a.description = "Deleted event " + to_string(eventID);
        history.push(a);
    }

    string undoLastAction() {
        if (history.isEmpty()) return "Nothing to undo.";
        Action a = history.pop();
        return "Undone: " + a.description;
    }

    string getName() const { return name; }
};

// ---------------------------------------------------------------
// Sample logs: written next to the program if they do not exist
// ---------------------------------------------------------------
static const char* NORMAL_LOG = R"(2001,2026-09-01T08:02:11,192.168.1.10,SuccessfulLogin
2002,2026-09-01T08:15:44,192.168.1.11,SuccessfulLogin
2003,2026-09-01T08:20:09,192.168.1.12,SuccessfulLogin
2004,2026-09-01T08:22:31,192.168.1.10,PrivilegeAccess
2005,2026-09-01T08:45:17,192.168.1.13,FailedLogin
2006,2026-09-01T08:46:02,192.168.1.13,SuccessfulLogin
2007,2026-09-01T09:01:55,192.168.1.14,SuccessfulLogin
2008,2026-09-01T09:10:23,192.168.1.10,FileTransfer
2009,2026-09-01T09:30:41,192.168.1.15,SuccessfulLogin
2010,2026-09-01T09:35:12,192.168.1.15,SuccessfulLogin
2011,2026-09-01T10:02:08,192.168.1.16,FailedLogin
2012,2026-09-01T10:03:19,192.168.1.16,SuccessfulLogin
2013,2026-09-01T10:20:47,192.168.1.11,PrivilegeAccess
2014,2026-09-01T10:45:33,192.168.1.17,SuccessfulLogin
2015,2026-09-01T11:00:00,192.168.1.12,FileTransfer
)";

static const char* ATTACK_LOG = R"(3001,2026-09-02T02:14:05,203.0.113.50,FailedLogin
3002,2026-09-02T02:14:22,203.0.113.50,FailedLogin
3003,2026-09-02T02:14:40,203.0.113.50,FailedLogin
3004,2026-09-02T02:14:58,203.0.113.50,FailedLogin
3005,2026-09-02T02:15:20,203.0.113.50,SuccessfulLogin
3006,2026-09-02T02:16:03,203.0.113.50,PrivilegeAccess
3007,2026-09-02T02:17:45,203.0.113.50,FileTransfer
3008,2026-09-02T02:30:11,198.51.100.23,FailedLogin
3009,2026-09-02T02:30:29,198.51.100.23,FailedLogin
3010,2026-09-02T02:31:02,198.51.100.23,SuccessfulLogin
3011,2026-09-02T02:32:14,198.51.100.23,PrivilegeAccess
3012,2026-09-02T02:34:50,198.51.100.23,FileTransfer
3013,2026-09-02T02:40:00,198.51.100.23,FileTransfer
3014,2026-09-02T03:05:18,192.0.2.77,FailedLogin
3015,2026-09-02T03:05:36,192.0.2.77,FailedLogin
3016,2026-09-02T03:06:01,192.0.2.77,FailedLogin
3017,2026-09-02T03:06:20,192.0.2.77,FailedLogin
3018,2026-09-02T03:06:45,192.0.2.77,FailedLogin
3019,2026-09-02T03:10:00,192.0.2.77,SuccessfulLogin
3020,2026-09-02T03:12:33,192.0.2.77,PrivilegeAccess
3021,2026-09-02T03:15:09,192.0.2.77,FileTransfer
)";

static const char* MIXED_LOG = R"(4001,2026-09-03T07:58:02,192.168.1.10,SuccessfulLogin
4002,2026-09-03T08:01:15,192.168.1.11,SuccessfulLogin
4003,2026-09-03T08:03:47,192.168.1.10,PrivilegeAccess
4004,2026-09-03T08:10:30,10.0.0.99,FailedLogin
4005,2026-09-03T08:10:52,10.0.0.99,FailedLogin
4006,2026-09-03T08:11:10,10.0.0.99,FailedLogin
4007,2026-09-03T08:20:00,192.168.1.12,SuccessfulLogin
4008,2026-09-03T08:25:41,192.168.1.10,FileTransfer
4009,2026-09-03T08:40:12,203.0.113.99,FailedLogin
4010,2026-09-03T08:40:33,203.0.113.99,FailedLogin
4011,2026-09-03T08:40:55,203.0.113.99,FailedLogin
4012,2026-09-03T08:41:20,203.0.113.99,SuccessfulLogin
4013,2026-09-03T08:42:48,203.0.113.99,PrivilegeAccess
4014,2026-09-03T08:44:30,203.0.113.99,FileTransfer
4015,2026-09-03T09:00:05,192.168.1.13,SuccessfulLogin
4016,2026-09-03T09:15:22,192.168.1.14,FailedLogin
4017,2026-09-03T09:15:44,192.168.1.14,SuccessfulLogin
)";

void writeSampleIfMissing(const string& filename, const char* content) {
    ifstream check(filename);
    if (check.is_open()) return;
    ofstream out(filename);
    if (out.is_open()) {
        out << content;
        cout << "Created sample log: " << filename << "\n";
    }
}

// ---------------------------------------------------------------
// Live monitoring (IN PROGRESS): ingests and prints new lines.
// Automatic risk alerts are not wired in yet - use option 5 afterwards.
// ---------------------------------------------------------------
void runLiveMonitoring(const string& path, Incident& incident, int pollSeconds, int maxPolls) {
    LiveLogReader reader(path);
    cout << "\n[CyberTrace] Live monitoring started on: " << path << "\n"
         << "Watching for " << maxPolls << " polls (~" << (pollSeconds * maxPolls)
         << "s). New lines appended to this file will be picked up automatically.\n"
         << "[In Progress] Automatic risk alerts during live mode are not yet wired up --\n"
         << "use option 5 after events come in to check risk manually.\n\n";

    for (int i = 0; i < maxPolls; ++i) {
        vector<string> newLines;
        if (reader.pollForNewEvents(newLines)) {
            for (const auto& line : newLines) {
                incident.ingestLine(line);
                Event e = Event::parseFromLine(line);
                cout << "[NEW EVENT] " << e.toString() << "\n";
            }
        }
        this_thread::sleep_for(chrono::seconds(pollSeconds));
    }
    cout << "\n[CyberTrace] Live monitoring window ended. Returning to menu.\n";
}

void printMenu() {
    cout << "\n===== CyberTrace =====\n"
         << "1. Load logs\n"
         << "2. View timeline\n"
         << "3. Search by Event ID\n"
         << "4. Search by IP address\n"
         << "5. Analyze risk for an IP\n"
         << "6. Generate report\n"
         << "7. Flag an event\n"
         << "8. Undo last action\n"
         << "9. Live monitor a log file [in progress]\n"
         << "10. Send notification (external alert) [pending - Phase 3]\n"
         << "0. Exit\n"
         << "Choice: ";
}

int main() {
    writeSampleIfMissing("sample_normal.txt", NORMAL_LOG);
    writeSampleIfMissing("sample_attack.txt", ATTACK_LOG);
    writeSampleIfMissing("sample_mixed.txt", MIXED_LOG);

    cout << "Investigator name: ";
    string invName;
    cin >> invName;

    Investigator investigator(invName);
    Incident incident("INC-001");
    investigator.assignIncident(&incident);

    int choice = -1;
    while (choice != 0) {
        printMenu();
        cin >> choice;

        switch (choice) {
            case 1: {
                string path;
                cout << "Log file path (e.g. sample_attack.txt): ";
                cin >> path;
                incident.loadLogs(path);
                break;
            }
            case 2: {
                for (const auto& e : incident.getTimeline()) cout << e.toString() << "\n";
                break;
            }
            case 3: {
                string id;
                cout << "Event ID: ";
                cin >> id;
                for (const auto& e : incident.searchByID(id)) cout << e.toString() << "\n";
                break;
            }
            case 4: {
                string ip;
                cout << "IP address: ";
                cin >> ip;
                for (const auto& e : incident.searchByIP(ip)) cout << e.toString() << "\n";
                break;
            }
            case 5: {
                string ip;
                cout << "IP address: ";
                cin >> ip;
                cout << "Risk score for " << ip << ": " << incident.analyzeRisk(ip) << "\n";
                if (incident.isSuspicious(ip)) cout << "  >> Suspicious attack pattern detected!\n";
                break;
            }
            case 6: {
                string report = incident.generateFinalReport();
                cout << report;
                ofstream outFile("investigation_report.txt");
                if (outFile.is_open()) {
                    outFile << report;
                    outFile.close();
                    cout << "\n(Report also saved to investigation_report.txt)\n";
                }
                break;
            }
            case 7: {
                int id;
                cout << "Event ID to flag: ";
                cin >> id;
                investigator.flagEvent(id);
                break;
            }
            case 8: {
                cout << investigator.undoLastAction() << "\n";
                break;
            }
            case 9: {
                string path;
                cout << "Log file path to watch: ";
                cin >> path;
                runLiveMonitoring(path, incident, 2, 15);
                break;
            }
            case 10: {
                cout << "*NOT WIRKING YET* External notifications (email/Slack) "
                     << "and session persistence are not yet implemented.\n"
                     << "Currently, alerts are console-only (see options 5 and 9).\n";
                break;
            }
           
