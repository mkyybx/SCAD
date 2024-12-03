#ifndef SCDETECTOR2_LRUCACHE_H
#define SCDETECTOR2_LRUCACHE_H

#include <unordered_map>
#include <list>
#include <string>

namespace SCDetector {
    template<typename K, typename V>
    class LRUCache {
    public:
        explicit LRUCache(size_t capacity) : capacity_(capacity) {}

        V get(const K &key) {
            auto it = cache_.find(key);
            assert(it != cache_.end()); // Just let it fail to avoid default initialization

            // Move the accessed key to the front of the list
            cacheList_.splice(cacheList_.begin(), cacheList_, it->second);
            return it->second->second;
        }

        void put(const K &key, const V &value) {
            auto it = cache_.find(key);

            // If key already exists, update its value and move it to the front
            if (it != cache_.end()) {
                it->second->second = value;
                cacheList_.splice(cacheList_.begin(), cacheList_, it->second);
                return;
            }

            // Otherwise, add the new key-value pair to the front of the list
            cacheList_.push_front(std::make_pair(key, value));
            cache_[key] = cacheList_.begin();

            // If cache has exceeded capacity, remove the least recently used item
            if (cache_.size() > capacity_) {
                auto last = cacheList_.end();
                last--;
                cache_.erase(last->first);
                cacheList_.pop_back();
            }
        }

        bool contains(const K& key) const {
            return cache_.find(key) != cache_.end();
        }

    private:
        size_t capacity_;
        std::list<std::pair<K, V>> cacheList_;
        std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> cache_;
    };
}

#endif //SCDETECTOR2_LRUCACHE_H
