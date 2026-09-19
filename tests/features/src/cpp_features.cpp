// C++ features: dynamic static initialization, exception handling metadata,
// RTTI and vtables, and COMDAT section groups.
//
// Exercises: .init_array with a guarded dynamic initializer, .eh_frame and
// .gcc_except_table from try/catch/throw, vtables and typeinfo landing in
// read-only-after-relocation memory, and SHT_GROUP COMDAT sections from
// template and inline instantiation.

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

// A non-trivial constructor forces a dynamic initializer and a guard variable.
struct Tracker {
    Tracker() : value(0x2a) {}
    virtual ~Tracker() = default;
    virtual int probe() const { return value; }
    int value;
};

static Tracker global_tracker;

struct Derived : Tracker {
    int probe() const override { return value + 1; }
};

// An explicit template instantiation emits a COMDAT group.
template <typename T>
T doubled(T value) {
    return value + value;
}
template int doubled<int>(int);

int main() {
    try {
        std::vector<std::string> names{"elfex"};
        if (names.empty()) {
            throw std::runtime_error("empty");
        }
        Derived derived;
        const Tracker &base = derived;
        std::printf("%d %d %d %s\n", global_tracker.probe(), base.probe(), doubled(7),
                    names.front().c_str());
        throw std::runtime_error("done");
    } catch (const std::exception &error) {
        std::printf("caught %s\n", error.what());
    }
    return 0;
}
