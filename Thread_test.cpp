#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "Thread support works!\n";
    return 0;
}
