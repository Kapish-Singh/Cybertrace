#include "ActionStack.h"
#include <stdexcept>

void ActionStack::push(const Action& a) {
    actions.push_back(a);
}

Action ActionStack::pop() {
    if (isEmpty()) throw std::runtime_error("ActionStack is empty");
    Action top = actions.back();
    actions.pop_back();
    return top;
}

Action ActionStack::peek() const {
    if (isEmpty()) throw std::runtime_error("ActionStack is empty");
    return actions.back();
}

bool ActionStack::isEmpty() const {
    return actions.empty();
}
