#ifndef SCDETECTOR2_SYNCQ_H
#define SCDETECTOR2_SYNCQ_H

#include <mutex>
#include <condition_variable>
#include <queue>
#include <random>
#include <vector>
#include <algorithm>
#include <set>
#include <cassert>
#include <atomic>
#include <boost/container_hash/hash.hpp>

using namespace std;
namespace SCDetector {
    using NoTag = uint;

    template<class T, size_t SIZE>
    class SyncQ {
    private:
        mutex m;
        condition_variable elementAdded;
        condition_variable elementRemoved;
        queue<T> buffer;
        bool destroyed = false;
    public:
        void put(T &&e) {
            unique_lock<mutex> l(m);
            elementRemoved.wait(l, [this] { return buffer.size() < SIZE || destroyed; });
            if (destroyed) {
                return;
            }
            buffer.push(std::move(e));
            elementAdded.notify_one();
        }

        bool putUnblocked(T &&e) {
            unique_lock<mutex> l(m);
            if (destroyed) {
                return true;
            }
            if (buffer.size() < SIZE) {
                buffer.push(std::move(e));
                elementAdded.notify_one();
                return true;
            }
            return false;
        }

        T get() {
            unique_lock<mutex> l(m);
            elementAdded.wait(l, [this] { return buffer.size() > 0 || destroyed; });
            if (destroyed) {
                return T();
            }
            T e = std::move(buffer.front());
            buffer.pop();
            elementRemoved.notify_one();
            return e;
        }

        T getUnblocked(const T &dummy) {
            unique_lock<mutex> l(m);
            if (destroyed) {
                return dummy;
            }
            if (buffer.size() > 0) {
                T e = std::move(buffer.front());
                buffer.pop();
                elementRemoved.notify_one();
                return e;
            }
            return dummy;
        }

        void destroy() {
            unique_lock<mutex> l(m);
            destroyed = true;
            elementAdded.notify_all();
            elementRemoved.notify_all();
        }

        ~SyncQ() {
            destroy();
        }
    };

    // No destroy as it's hard to implement correctly
    template<class T, class C, size_t SIZE>
    class FairSyncMultiQ {
    private:
        std::unordered_map<C, std::queue<T>, boost::hash<C>> buffers;
        std::unordered_map<C, uint64_t, boost::hash<C>> chances;
        std::unordered_map<C, std::atomic<bool>, boost::hash<C>> isQueueEmpty;
        std::mutex mutex;
        std::condition_variable notFull;
        std::condition_variable notEmpty;
        std::random_device rd;
        std::mt19937 gen;
        size_t cSize;

        C selectQueue(std::unique_lock<std::mutex> &l) {
            if (cSize == 1) {
                return buffers.begin()->first;
            }

            uint64_t total_weight = 0;
            notEmpty.wait(l, [this, &total_weight] {
                for (const auto &pair: chances) {
                    if (!isQueueEmpty[pair.first]) {
                        total_weight += pair.second;
                    }
                }
                return total_weight > 0;
            });

            assert(total_weight > 0);

            std::uniform_int_distribution<uint64_t> dist(0, total_weight - 1);
            uint64_t value = dist(gen);

            for (const auto &pair: chances) {
                if (!isQueueEmpty[pair.first]) {
                    if (value < pair.second) {
                        return pair.first;
                    }
                    value -= pair.second;
                }
            }
            // In theory, it should never reach this line.
            throw std::runtime_error("No available queues!");
        }

    public:
        std::atomic<uint64_t> totalBufferLen;
        std::atomic<uint64_t> processedElements;
        NoTag defaultNoTagVal = NoTag();

        FairSyncMultiQ(const std::unordered_map<C, uint64_t, boost::hash<C>> &chances) : gen(rd()), chances(chances),
                                                                                         totalBufferLen(0),
                                                                                         processedElements(0),
                                                                                         cSize(chances.size()) {
            for (const auto &pKeyChance: chances) {
                auto key = pKeyChance.first;
                buffers.emplace(std::piecewise_construct, std::forward_as_tuple(key), std::tuple<>());
                isQueueEmpty[key] = true;
            }
            assert(cSize > 0);
        }

        FairSyncMultiQ() : gen(rd()), totalBufferLen(0), processedElements(0) {
            static_assert(std::is_same<C, NoTag>::value);
            chances[defaultNoTagVal] = 1;
            for (const auto &pKeyChance: chances) {
                auto key = pKeyChance.first;
                buffers.emplace(std::piecewise_construct, std::forward_as_tuple(key), std::tuple<>());
                isQueueEmpty[key] = true;
            }
            cSize = chances.size();
        }

        void put(const C &c, T &&e) {
            std::unique_lock<std::mutex> l(mutex);
            notFull.wait(l, [this, &c] { return buffers.at(c).size() < SIZE; });
            buffers.at(c).push(std::move(e));
            totalBufferLen++;
            processedElements++;
            isQueueEmpty.at(c) = false;
            notEmpty.notify_one();
        }

        void putOneClass(T &&e) {
            assert(cSize == 1);
            put(defaultNoTagVal, std::move(e));
        }

        bool putUnblocked(const C &c, T &&e) {
            std::unique_lock<std::mutex> l(mutex);
            if (buffers.at(c).size() < SIZE) {
                buffers.at(c).push(std::move(e));
                totalBufferLen++;
                processedElements++;
                isQueueEmpty.at(c) = false;
                notEmpty.notify_one();
                return true;
            }
            return false;
        }

        T get() {
            std::unique_lock<std::mutex> l(mutex);
            const C &&c = selectQueue(l);
            notEmpty.wait(l, [this, &c] { return buffers.at(c).size() > 0; });
            auto e = std::move(buffers.at(c).front());
            buffers.at(c).pop();
            totalBufferLen--;
            isQueueEmpty.at(c) = buffers.at(c).empty();
            notFull.notify_one();
            return e;
        }

        // Not usable due to selectQueue is blocking
//        T getUnblocked(const T &dummy) {
//            std::unique_lock<std::mutex> l(mutex);
//            const C &&c = selectQueue();
//            if (buffers.at(c).size() > 0) {
//                T e = std::move(buffers.at(c).front());
//                buffers.at(c).pop();
//                totalBufferLen--;
//                isQueueEmpty.at(c) = buffers.at(c).empty();
//                notFull.notify_one();
//                return e;
//            }
//            return dummy;
//        }
    };
}

#endif //SCDETECTOR2_SYNCQ_H
