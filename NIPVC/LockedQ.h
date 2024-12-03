#ifndef SCDETECTOR2_LOCKEDQ_H
#define SCDETECTOR2_LOCKEDQ_H

#include <mutex>
#include <queue>
#include <vector>
#include <condition_variable>

using namespace std;
namespace SCDetector {
    template<class T>
    class LockedQ {
    private:
        mutex m;
        queue<T> buffer;
    public:
        void put(T &&e) {
            lock_guard<mutex> lock(m);
            buffer.push(std::move(e));
        }

        T get(const T &noElement) {
            lock_guard<mutex> lock(m);
            if (!buffer.empty()) {
                T e = std::move(buffer.front());
                buffer.pop();
                return e;
            } else {
                return noElement;
            }
        }

        size_t size() {
            lock_guard<mutex> lock(m);
            return buffer.size();
        }
    };

    template<class T, size_t SIZE>
    class RandomizedLockedQ {
    private:
        mutex m;
        vector<T> buffer;
        condition_variable elementRemoved;
    public:
        void put(T &&e) {
            unique_lock<mutex> l(m);
            elementRemoved.wait(l, [this] { return buffer.size() < SIZE; });
            buffer.push_back(std::move(e));
        }

        bool putUnblocked(T &&e) {
            unique_lock<mutex> l(m);
            if (buffer.size() < SIZE) {
                buffer.push_back(std::move(e));
                return true;
            }
            return false;
        }

        T get(const T &noElement) {
            lock_guard<mutex> lock(m);
            if (!buffer.empty()) {
                size_t random_index = rand() % buffer.size();
                T e = std::move(buffer.at(random_index));
                buffer[random_index] = std::move(buffer.back());
                buffer.pop_back();
                elementRemoved.notify_one();
                return e;
            } else {
                return noElement;
            }
        }

        size_t size() {
            lock_guard<mutex> lock(m);
            return buffer.size();
        }
    };
}

#endif //SCDETECTOR2_SYNCQ_H
