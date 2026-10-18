#include "Investigator.h"

Investigator::Investigator(const std::string& investigatorName)
    : name(investigatorName), currentIncident(nullptr) {}

void Investigator::assignIncident(Incident* incident) {
    currentIncident = incident;
}

void Investigator::flagEvent(int eventID) {
    Action a;
    a.type = "FLAG_EVENT";
    a.description = "Flagged event " + std::to_string(eventID);
    a.timestamp = "";
    history.push(a);
}

void Investigator::deleteEvent(int eventID) {
    Action a;
    a.type = "DELETE_EVENT";
    a.description = "Deleted event " + std::to_string(eventID);
    a.timestamp = "";
    history.push(a);
}

std::string Investigator::undoLastAction() {
    if (history.isEmpty()) {
        return "Nothing to undo.";
    }
    Action a = history.pop();
    return "Undone: " + a.description;
}

std::string Investigator::getName() const {
    return name;
}
