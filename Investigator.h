#pragma once
#include "ActionStack.h"
#include "Incident.h"
#include <string>

// Investigator represents the person operating the tool.
// Owns the undo history and works on one active Incident at a time.
class Investigator {
private:
    std::string name;
    ActionStack history;
    Incident* currentIncident;

public:
    explicit Investigator(const std::string& investigatorName);

    void assignIncident(Incident* incident);

    void flagEvent(int eventID);
    void deleteEvent(int eventID);
    std::string undoLastAction();   // returns description of what was undone

    std::string getName() const;
};
