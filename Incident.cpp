#include "Incident.h"
#include <fstream>
#include <iostream>

Incident::Incident(const std::string& id) : incidentID(id) {}

void Incident::ingestLine(const std::string& line) {
    if (line.empty()) return;
    Event e = Event::parseFromLine(line);
    timeline.insertEvent(e);
    idIndex.insert(std::to_string(e.getEventID()), e);
    ipIndex.insert(e.getIPAddress(), e);
}

bool Incident::loadLogs(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cout << "Could not open log file: " << filepath << "\n";
        return false;
    }

    std::string line;
    int loaded = 0;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        ingestLine(line);
        loaded++;
    }
    std::cout << "Loaded " << loaded << " events from " << filepath << "\n";
    return true;
}

std::vector<Event> Incident::getTimeline() const {
    return timeline.traverse();
}

std::vector<Event> Incident::searchByID(const std::string& id) const {
    return idIndex.find(id);
}

std::vector<Event> Incident::searchByIP(const std::string& ip) const {
    return ipIndex.find(ip);
}

int Incident::analyzeRisk(const std::string& ip) const {
    auto events = ipIndex.find(ip);
    return analyzer.calculateRiskScore(events);
}

bool Incident::isSuspicious(const std::string& ip) const {
    auto events = ipIndex.find(ip);
    return analyzer.detectSuspiciousSequence(events);
}

std::string Incident::generateFinalReport() const {
    auto all = timeline.traverse();

    // Collect unique IPs
    std::vector<std::string> seenIPs;
    for (const auto& e : all) {
        bool found = false;
        for (const auto& ip : seenIPs) if (ip == e.getIPAddress()) { found = true; break; }
        if (!found) seenIPs.push_back(e.getIPAddress());
    }

    std::vector<Event> flagged;
    int totalRisk = 0;
    for (const auto& ip : seenIPs) {
        auto ipEvents = ipIndex.find(ip);
        if (analyzer.detectSuspiciousSequence(ipEvents)) {
            for (const auto& e : ipEvents) flagged.push_back(e);
            totalRisk += analyzer.calculateRiskScore(ipEvents);
        }
    }

    return reporter.generateReport(all, flagged, totalRisk);
}

std::string Incident::getIncidentID() const {
    return incidentID;
}
