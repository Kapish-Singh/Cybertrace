#include "HashTable.h"

HashTable::HashTable() : buckets(TABLE_SIZE) {}

int HashTable::hashKey(const std::string& key) const {
    unsigned long hash = 0;
    for (char c : key) {
        hash = hash * 31 + static_cast<unsigned char>(c);
    }
    return static_cast<int>(hash % TABLE_SIZE);
}

void HashTable::insert(const std::string& key, const Event& e) {
    int index = hashKey(key);
    buckets[index].push_back({key, e});
}

std::vector<Event> HashTable::find(const std::string& key) const {
    std::vector<Event> results;
    int index = hashKey(key);
    for (const auto& pair : buckets[index]) {
        if (pair.first == key) {
            results.push_back(pair.second);
        }
    }
    return results;
}

bool HashTable::remove(const std::string& key, int eventID) {
    int index = hashKey(key);
    auto& bucket = buckets[index];
    for (auto it = bucket.begin(); it != bucket.end(); ++it) {
        if (it->first == key && it->second.getEventID() == eventID) {
            bucket.erase(it);
            return true;
        }
    }
    return false;
}
