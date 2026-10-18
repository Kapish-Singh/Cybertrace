#include "Incident.h"
#include "Investigator.h"
#include "LiveLogReader.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>

void runLiveMonitoring(const std::string& path, Incident& incident, int pollSeconds, int maxPolls) {
    LiveLogReader reader(path);
    std::cout << "\n[CyberTrace] Live monitoring started on: " << path << "\n"
              << "Watching for " << maxPolls << " polls (~" << (pollSeconds * maxPolls)
              << "s). New lines appended to this file will be picked up automatically.\n\n";

    for (int i = 0; i < maxPolls; ++i) {
        std::vector<std::string> newLines;
        if (reader.pollForNewEvents(newLines)) {
            for (const auto& line : newLines) {
                incident.ingestLine(line);
                Event e = Event::parseFromLine(line);
                std::cout << "[NEW EVENT] " << e.toString() << "\n";

                if (incident.isSuspicious(e.getIPAddress())) {
                    int score = incident.analyzeRisk(e.getIPAddress());
                    std::cout << "  >> RISK ALERT for " << e.getIPAddress()
                              << " (score: " << score << ")\n";
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(pollSeconds));
    }
    std::cout << "\n[CyberTrace] Live monitoring window ended. Returning to menu.\n";
}

void printMenu() {
    std::cout << "\n===== CyberTrace =====\n"
              << "1. Load logs\n"
              << "2. View timeline\n"
              << "3. Search by Event ID\n"
              << "4. Search by IP address\n"
              << "5. Analyze risk for an IP\n"
              << "6. Generate report\n"
              << "7. Flag an event\n"
              << "8. Undo last action\n"
              << "9. Live monitor a log file\n"
              << "0. Exit\n"
              << "Choice: ";
}

int main() {
    std::cout << "Investigator name: ";
    std::string invName;
    std::cin >> invName;

    Investigator investigator(invName);
    Incident incident("INC-001");
    investigator.assignIncident(&incident);

    int choice = -1;
    while (choice != 0) {
        printMenu();
        std::cin >> choice;

        switch (choice) {
            case 1: {
                std::string path;
                std::cout << "Log file path (e.g. logs/sample_logs.txt): ";
                std::cin >> path;
                incident.loadLogs(path);
                break;
            }
            case 2: {
                for (const auto& e : incident.getTimeline()) {
                    std::cout << e.toString() << "\n";
                }
                break;
            }
            case 3: {
                std::string id;
                std::cout << "Event ID: ";
                std::cin >> id;
                for (const auto& e : incident.searchByID(id)) {
                    std::cout << e.toString() << "\n";
                }
                break;
            }
            case 4: {
                std::string ip;
                std::cout << "IP address: ";
                std::cin >> ip;
                for (const auto& e : incident.searchByIP(ip)) {
                    std::cout << e.toString() << "\n";
                }
                break;
            }
            case 5: {
                std::string ip;
                std::cout << "IP address: ";
                std::cin >> ip;
                int score = incident.analyzeRisk(ip);
                std::cout << "Risk score for " << ip << ": " << score << "\n";
                if (incident.isSuspicious(ip)) {
                    std::cout << "  >> Suspicious attack pattern detected!\n";
                }
                break;
            }
            case 6: {
                std::string report = incident.generateFinalReport();
                std::cout << report;

                std::ofstream outFile("investigation_report.txt");
                if (outFile.is_open()) {
                    outFile << report;
                    outFile.close();
                    std::cout << "\n(Report also saved to investigation_report.txt)\n";
                }
                break;
            }
            case 7: {
                int id;
                std::cout << "Event ID to flag: ";
                std::cin >> id;
                investigator.flagEvent(id);
                break;
            }
            case 8: {
                std::cout << investigator.undoLastAction() << "\n";
                break;
            }
            case 9: {
                std::string path;
                std::cout << "Log file path to watch: ";
                std::cin >> path;
                runLiveMonitoring(path, incident, 2, 15);
                break;
            }
            case 0:
                std::cout << "Exiting CyberTrace. Goodbye, " << investigator.getName() << ".\n";
                break;
            default:
                std::cout << "Invalid choice.\n";
        }
    }

    return 0;
}
