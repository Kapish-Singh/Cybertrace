#pragma once
#include "Event.h"
#include <string>
#include <vector>
#include <list>

class HashTable {
private:
    static const int TABLE_SIZE = 101;
    std::vector<std::list<std::pair<std::string, Event>>> buckets;

    int hashKey(const std::string& key) const;

public:
    HashTable();

    void insert(const std::string& key, const Event& e);
    std::vector<Event> find(const std::string& key) const;
    bool remove(const std::string& key, int eventID);
};
