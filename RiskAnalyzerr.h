#pragma once
#include "Event.h"
#include <vector>

class RiskAnalyzer {
public:
    int calculateRiskScore(const std::vector<Event>& eventsForIP) const;
    bool detectSuspiciousSequence(const std::vector<Event>& eventsForIP) const;
};
