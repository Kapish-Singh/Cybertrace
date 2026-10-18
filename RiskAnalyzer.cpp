#include "RiskAnalyzer.h"

int RiskAnalyzer::calculateRiskScore(const std::vector<Event>& eventsForIP) const {
    int score = 0;
    for (const auto& e : eventsForIP) {
        const std::string& type = e.getEventType();
        if (type == "FailedLogin") score += 1;
        else if (type == "SuccessfulLogin") score += 2;
        else if (type == "PrivilegeAccess") score += 5;
        else if (type == "FileTransfer") score += 7;
    }

    if (detectSuspiciousSequence(eventsForIP)) {
        score += 10;
    }

    return score;
}

bool RiskAnalyzer::detectSuspiciousSequence(const std::vector<Event>& eventsForIP) const {
    int stage = 0;
    for (const auto& e : eventsForIP) {
        const std::string& type = e.getEventType();
        if (stage == 0 && type == "FailedLogin") {
            stage = 1;
        } else if (stage == 1 && type == "SuccessfulLogin") {
            stage = 2;
        } else if (stage == 2 && type == "PrivilegeAccess") {
            stage = 3;
        } else if (stage == 3 && type == "FileTransfer") {
            return true;
        }
    }
    return false;
}
