#pragma once
#include <string>
#include <vector>
struct Action {
    std::string type;         // e.g. "FLAG_EVENT", "DELETE_EVENT"
    std::string description;
    std::string timestamp;
};

class ActionStack {
private:
    std::vector<Action> actions;

public:
    void push(const Action& a);
    Action pop();
    Action peek() const;
    bool isEmpty() const;
};
