#include "ReportGenerator.h"
#include <sstream>

std::string ReportGenerator::generateReport(const std::vector<Event>& timeline,
                                             const std::vector<Event>& flaggedEvents,
                                             int riskScore) const {
    std::stringstream report;
    report << "===== CyberTrace Investigation Report =====\n\n";

    report << "-- Timeline (" << timeline.size() << " events) --\n";
    for (const auto& e : timeline) {
        report << "  " << e.toString() << "\n";
    }

    report << "\n-- Flagged Suspicious Events --\n";
    if (flaggedEvents.empty()) {
        report << "  None detected.\n";
    } else {
        for (const auto& e : flaggedEvents) {
            report << "  " << e.toString() << "\n";
        }
    }

    report << "\n-- Risk Score: " << riskScore << " --\n";
    report << "============================================\n";

    return report.str();
}
