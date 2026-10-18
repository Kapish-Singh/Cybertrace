#include "LiveLogReader.h"

LiveLogReader::LiveLogReader(const std::string& path) : filepath(path), lastPosition(0) {
    logFile.open(filepath);
}

LiveLogReader::~LiveLogReader() {
    if (logFile.is_open()) logFile.close();
}

bool LiveLogReader::pollForNewEvents(std::vector<std::string>& newLines) {
    logFile.clear();
    logFile.seekg(lastPosition);

    std::string line;
    bool foundNew = false;

    while (std::getline(logFile, line)) {
        if (!line.empty()) {
            newLines.push_back(line);
            foundNew = true;
        }
    }

    logFile.clear();
    lastPosition = logFile.tellg();

    return foundNew;
}
