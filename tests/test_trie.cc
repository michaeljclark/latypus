#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <vector>
#include <map>
#include <unordered_map>

#include "trie.h"


void trie_add(trie<uint32_t> &trie, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        trie.insert(word, (uint32_t)i++);
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / words.size();
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, words.size(), total_ns, item_ns);
}

void trie_lookup(trie<uint32_t> &trie, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        if (trie.find(word) == i) i++;
        else printf("%s couldn't find \"%s\"\n", __func__, word.c_str());
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / i;
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, i, total_ns, item_ns);
}

void map_add(std::map<std::string,uint32_t> &map, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        map.insert(std::pair<std::string,uint32_t>(word, i));
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / words.size();
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, words.size(), total_ns, item_ns);
}

void map_lookup(std::map<std::string,uint32_t> &map, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        auto mi = map.find(word);
        if (mi != map.end()) i++;
        else printf("%s couldn't find \"%s\"\n", __func__, word.c_str());
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / i;
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, i, total_ns, item_ns);
}

void unordered_map_add(std::unordered_map<std::string,uint32_t> &map, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        map.insert(std::pair<std::string,uint32_t>(word, i));
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / words.size();
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, words.size(), total_ns, item_ns);
}

void unordered_map_lookup(std::unordered_map<std::string,uint32_t> &map, std::vector<std::string> &words)
{
    size_t i = 0;
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (auto word: words) {
        auto mi = map.find(word);
        if (mi != map.end()) i++;
        else printf("%s couldn't find \"%s\"\n", __func__, word.c_str());
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / i;
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, i, total_ns, item_ns);
}

void read_words(std::vector<std::string> &words, std::string filename)
{
    char buf[1024];
    FILE *file = fopen("/usr/share/dict/words", "r");
    if (!file) {
        fprintf(stderr, "error: %s", strerror(errno));
        exit(0);
    }
    const auto t1 = std::chrono::high_resolution_clock::now();
    char *line;
    while((line = fgets(buf, sizeof(buf), file))) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        words.push_back(line);
    }
    const auto t2 = std::chrono::high_resolution_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    uint64_t item_ns = total_ns / words.size();
    fclose(file);
    printf("%-20s items=(%9lu) total_time=(%12" PRIu64 " ns) item_time=(%6" PRIu64 " ns)\n",
           __func__, words.size(), total_ns, item_ns);
}

int main(int argc, char **argv)
{
    std::vector<std::string> words;
    read_words(words, "/usr/share/dict/words");

    trie<uint32_t> mt;
    trie_add(mt, words);
    trie_lookup(mt, words);

    std::map<std::string,uint32_t> map;
    map_add(map, words);
    map_lookup(map,words);

    std::unordered_map<std::string,uint32_t> unordered_map;
    unordered_map_add(unordered_map, words);
    unordered_map_lookup(unordered_map,words);
}
