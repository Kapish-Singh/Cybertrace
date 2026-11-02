#pragma once
#include "Event.h"
#include "EventList.h"
#include "HashTable.h"
#include "RiskAnalyzer.h"
#include "ReportGenerator.h"
#include <string>
#include <vector>

// Incident owns all the core data structures for ONE investigation session.
// This is where encapsulation and abstraction live: callers interact only
// through these public methods and never touch EventList/HashTable directly.
class Incident {
private:
    std::string incidentID;
    EventList timeline;
    HashTable idIndex;
    HashTable ipIndex;
    RiskAnalyzer analyzer;
    ReportGenerator reporter;

public:
    explicit Incident(const std::string& id);

    bool loadLogs(const std::string& filepath);          // reads a log file into the structures
    void ingestLine(const std::string& line);             // adds one parsed line (used by live mode)

    std::vector<Event> getTimeline() const;
    std::vector<Event> searchByID(const std::string& id) const;
    std::vector<Event> searchByIP(const std::string& ip) const;

    int analyzeRisk(const std::string& ip) const;          // abstraction: hides scanning logic
    bool isSuspicious(const std::string& ip) const;

    std::string generateFinalReport() const;               // builds the full report across all IPs
    std::string getIncidentID() const;
};
