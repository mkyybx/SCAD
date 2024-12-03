#ifndef SCDETECTOR2_DIJKSTRA_H
#define SCDETECTOR2_DIJKSTRA_H

#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <memory>

namespace SCDetector {
    template<class T>
    class Dijkstra {
    public:
        static void dijkstra(const std::unordered_map<T, std::unordered_map<T, uint64_t>> &data, const T &start,
                             std::unordered_map<T, T> &prev) {
            // Define max uint64_t value
            const uint64_t MAX_UINT64 = std::numeric_limits<uint64_t>::max();

            // Create a map to hold the shortest distances from start to each node
            std::unordered_map<T, uint64_t> dist;

            // Custom comparator for priority queue
            auto comp = [&](const T &a, const T &b) {
                return dist[a] > dist[b];
            };

            // Initialize priority queue
            std::priority_queue<T, std::vector<T>, decltype(comp)> pq(comp);

            // Initialize distances and previous node map
            for (const auto &pair: data) {
                if (pair.first == start) {
                    dist[start] = 0;
                } else {
                    dist[pair.first] = MAX_UINT64;
                }
                for (const auto &colPair: pair.second) {
                    if (colPair.first == start) {
                        dist[start] = 0;
                    } else {
                        dist[colPair.first] = MAX_UINT64;
                    }
                }
//                prev[pair.first] = T();  // Initialize to default value
            }

            // If start node isn't in the data, return because we can't do anything
            if (dist.find(start) == dist.end()) {
                return;
            }

            // Add start to the priority queue
            pq.push(start);

            while (!pq.empty()) {
                // Get the node with the smallest distance
                T u = pq.top();
                pq.pop();

                // If this distance is the maximum, then remaining nodes are unreachable
                if (dist[u] == MAX_UINT64) break;

                // Visit all neighbors of u
                if (data.contains(u)) {
                    for (const auto &neighbor: data.at(u)) {
                        T v = neighbor.first;
                        uint64_t altDist = dist[u] == MAX_UINT64 ? MAX_UINT64 : dist[u] + neighbor.second;
                        // Check for wrap around of uint64_t
                        if (altDist < dist[u]) {
                            altDist = MAX_UINT64;
                        }
                        if (altDist < dist[v]) {
                            dist[v] = altDist;
                            prev[v] = u;
                            pq.push(v);
                        }
                    }
                }
            }

            // Remove nodes from prev that are not reachable from start
//            for (auto it = prev.begin(); it != prev.end();) {
//                if (dist[it->first] == MAX_UINT64) {
//                    it = prev.erase(it);
//                } else {
//                    ++it;
//                }
//            }
        }

        template<class U>
        static std::shared_ptr<std::unordered_map<T, std::unordered_map<T, uint64_t>>>
        convertToDistanceOneDijkstraMap(const std::unordered_map<T, std::unordered_map<T, U>> &input) {
            auto ret = std::make_shared<std::unordered_map<T, std::unordered_map<T, uint64_t>>>();
            for (const auto &pFromToMap: input) {
                for (const auto &pToData: pFromToMap.second) {
                    (*ret)[pFromToMap.first][pToData.first] = 1;
                }
            }
            return ret;
        }
    };
}


#endif //SCDETECTOR2_DIJKSTRA_H
