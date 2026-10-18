#include "Event.h"
#include <sstream>

Event::Event() : eventID(0) {}

Event::Event(int id, const std::string& time, const std::string& ip, const std::string& type)
    : eventID(id), timestamp(time), ipAddress(ip), eventType(type) {}

int Event::getEventID() const { return eventID; }
std::string Event::getTimestamp() const { return timestamp; }
std::string Event::getIPAddress() const { return ipAddress; }
std::string Event::getEventType() const { return eventType; }

std::string Event::toString() const {
    return "[" + std::to_string(eventID) + "] " + timestamp + " " + ipAddress + " " + eventType;
}

Event Event::parseFromLine(const std::string& line) {
    std::stringstream ss(line);
    std::string idStr, time, ip, type;

    std::getline(ss, idStr, ',');
    std::getline(ss, time, ',');
    std::getline(ss, ip, ',');
    std::getline(ss, type, ',');

    int id = idStr.empty() ? 0 : std::stoi(idStr);
    return Event(id, time, ip, type);
}
