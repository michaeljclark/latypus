//
//  trie.h
//

#ifndef trie_h
#define trie_h

template<typename T>
struct trie_node
{
    T value;
    trie_node *chars[256];
    
    trie_node() : value(), chars() {}
    
    ~trie_node()
    {
        for (int i = 0; i < 256; i++) {
            if (chars[i]) {
                delete chars[i];
            }
        }
    }
};

template<typename T>
struct trie
{
    typedef std::pair<std::string,uint32_t> trie_entry;
    
    trie_node<trie_entry> *root_node;
    
    trie()
    {
        root_node = new trie_node<trie_entry>();
    }
    
    ~trie()
    {
        delete root_node;
    }
    
    void insert(trie_node<trie_entry> *t, trie_entry value)
    {
        int c;
        const char *p = value.first.c_str();
        while ((c = *p++)) {
            if (t->chars[c] == nullptr) {
                t->chars[c] = new trie_node<trie_entry>();
            }
            t = t->chars[c];
        }
        t->value = value;
    }
    
    T find(trie_node<trie_entry> *t, std::string key)
    {
        int c;
        const char *p = key.c_str();
        while ((c = *p++)) {
            if (t->chars[c] == nullptr) {
                return T();
            }
            t = t->chars[c];
        }
        return t->value.second;
    }
    
    trie_entry& find_nearest(trie_node<trie_entry> *t, std::string key)
    {
        static trie_entry null_entry;
        
        int c;
        trie_entry *nearest = &null_entry;
        const char *p = key.c_str();
        while ((c = *p++)) {
            if (t->chars[c] == nullptr) {
                return *nearest;
            }
            t = t->chars[c];
            if (t->value.second) {
                nearest = &t->value;
            }
        }
        return *nearest;
    }
    
    void insert(std::string key, T value)
    {
        return insert(root_node, trie_entry(key, value));
    }
    
    T find(std::string key)
    {
        return find(root_node, key);
    }
    
    trie_entry find_nearest(std::string key)
    {
        return find_nearest(root_node, key);
    }
};

#endif
