#pragma once
#include <string>

class Event {
private:
    int eventID;
    std::string timestamp;
    std::string ipAddress;
    std::string eventType;   // FailedLogin, SuccessfulLogin, PrivilegeAccess, FileTransfer, etc.

public:
    Event();
    Event(int id, const std::string& time, const std::string& ip, const std::string& type);

    int getEventID() const;
    std::string getTimestamp() const;
    std::string getIPAddress() const;
    std::string getEventType() const;

    std::string toString() const;

    static Event parseFromLine(const std::string& line);
};
