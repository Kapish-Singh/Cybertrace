#pragma once
#include "Event.h"
#include <vector>
#include <string>

class ReportGenerator {
public:
    std::string generateReport(const std::vector<Event>& timeline,
                                const std::vector<Event>& flaggedEvents,
                                int riskScore) const;
};
