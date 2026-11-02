#pragma once
#include "Event.h"
#include <vector>
struct EventNode {
    Event data;
    EventNode* next;
    EventNode(const Event& e) : data(e), next(nullptr) {}
};

class EventList {
private:
    EventNode* head;
    EventNode* tail;
    int count;

public:
    EventList();
    ~EventList();

    void insertEvent(const Event& e);
    std::vector<Event> traverse() const;
    Event* findByID(int id) const;
    int size() const;
};
