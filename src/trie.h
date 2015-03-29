//
//  trie.h
//

#ifndef trie_h
#define trie_h

struct trie_node;
typedef std::vector<trie_node*> trie_node_list;

enum trie_node_type
{
    trie_node_type_branch,
    trie_node_type_leaf,
};

struct trie_node
{
    std::string         prefix;
    
    trie_node(std::string &prefix) : prefix(prefix) {}
    virtual ~trie_node() {}
    
    virtual trie_node_type get_type() = 0;
};

template <typename T>
struct trie_branch_node : trie_node
{
    trie_node_list    nodes;
    
    trie_node_type get_type() { return trie_node_type_branch; }

    trie_branch_node(std::string prefix) : trie_node(prefix) {}
};

template <typename T>
struct trie_leaf_node : trie_node
{
    T                   val;

    trie_node_type get_type() { return trie_node_type_leaf; }
    
    trie_leaf_node(std::string prefix, T val) : trie_node(prefix), val(val) {}
};

template <typename T>
struct trie
{
    trie_node* root_node;
    
    typedef std::pair<std::string,T> pair_type;
    typedef std::vector<pair_type> vec_type;
    typedef trie_leaf_node<T> leaf_type;
    typedef trie_branch_node<T> branch_type;
    
    static struct {
        bool operator()(const trie_node *lhs, const trie_node *rhs) { return lhs->prefix < rhs->prefix; }
    } node_prefix_cmp;
    
    trie() : root_node(nullptr) {}
    
    static void sort_nodes(branch_type *node)
    {
        std::sort(node->nodes.begin(), node->nodes.end(), node_prefix_cmp);
    }
    
    static void print(trie_node *node, size_t offset, int key_width, bool do_print)
    {
        int pad = (int)(offset + node->prefix.length());
        if (node->get_type() == trie_node_type_leaf) {
            auto lnode = static_cast<trie_leaf_node<T>*>(node);
            if (do_print)
                std::cout << std::setfill(' ') << std::setw(pad) << lnode->prefix
                          << std::setw(key_width - pad) << " " << ":= " << lnode->val << std::endl;
        }
        if (node->get_type() == trie_node_type_branch) {
            auto inode = static_cast<trie_branch_node<T>*>(node);
            if (do_print)
                std::cout << std::setfill(' ') << std::setw(pad) << inode->prefix
                          << std::endl;
            for (auto cnode : inode->nodes) {
                print(cnode, offset + inode->prefix.length(), key_width, true);
            }
        }
    }
    
    void print()
    {
        if (root_node) print(root_node, 0, 60, false);
    }
    
    void find_node_internal(std::string &key, trie_node* &node, trie_node* &parent,
                            size_t &prefix_offset, size_t &key_offset, size_t &child_index,
                            std::vector<trie_node*> *stack = nullptr)
    {
        prefix_offset = key_offset = child_index = 0;
        while(key_offset < key.length()) {
        next:
            if (prefix_offset < node->prefix.length() &&
                node->prefix[prefix_offset] == key[key_offset])
            {
                prefix_offset++; key_offset++;
                continue;
            }
            else if (node->get_type() == trie_node_type_leaf)
            {
                if (prefix_offset == node->prefix.length()) {
                    // matched to end of leaf
                    if (stack) stack->push_back(node);
                }
                break;
            }
            else if (node->get_type() == trie_node_type_branch)
            {
                if (prefix_offset == node->prefix.length()) {
                    // matched to end of branch
                    if (stack) stack->push_back(node);
                    
                    branch_type* branch = static_cast<branch_type*>(node);
                    child_index = 0;
                    for (auto child_node : branch->nodes) {
                        // matched child
                        if (child_node->prefix.length() > 0 && child_node->prefix[0] == key[key_offset]) {
                            prefix_offset = 0;
                            parent = node;
                            node = child_node;
                            goto next;
                        }
                        child_index++;
                    }
                    break;
                } else {
                    // partial match
                    break;
                }
            }
        }
    }
    
    bool insert(std::string key, T val)
    {
        if (!root_node) {
            root_node = new branch_type("");
            static_cast<branch_type*>(root_node)->nodes.push_back(new leaf_type(key, val));
            return true;
        }

        // find nearest matching node
        trie_node *node = root_node, *parent = nullptr;
        size_t prefix_offset, key_offset, child_index;
        find_node_internal(key, node, parent, prefix_offset, key_offset, child_index);
        
        // exact match, duplicate key
        if (key.length() == key_offset) {
            return false;
        }
        
        // insert new leaf node
        if (node->get_type() == trie_node_type_leaf)
        {
            // split leaf and create new branch
            std::string parent_prefix = node->prefix.substr(0, prefix_offset);
            std::string old_child_prefix = node->prefix.substr(prefix_offset);
            std::string new_child_prefix = key.substr(key_offset);
            branch_type* new_branch = new branch_type(parent_prefix);
            leaf_type* old_leaf = new leaf_type(old_child_prefix, static_cast<leaf_type*>(node)->val);
            leaf_type* new_leaf = new leaf_type(new_child_prefix, val);
            new_branch->nodes.push_back(old_leaf);
            new_branch->nodes.push_back(new_leaf);
            sort_nodes(new_branch);
            static_cast<branch_type*>(parent)->nodes[child_index] = new_branch;
            delete node;
        }
        else if (node->get_type() == trie_node_type_branch)
        {
            if (prefix_offset == node->prefix.length())
            {
                // add new leaf
                std::string new_child_prefix = key.substr(key_offset);
                leaf_type* new_leaf = new leaf_type(new_child_prefix, val);
                static_cast<branch_type*>(node)->nodes.push_back(new_leaf);
                sort_nodes(static_cast<branch_type*>(node));
            }
            else if (prefix_offset < node->prefix.length())
            {
                // split branch, copy child nodes and add new leaf
                std::string parent_prefix = node->prefix.substr(0, prefix_offset);
                std::string old_child_prefix = node->prefix.substr(prefix_offset);
                std::string new_child_prefix = key.substr(key_offset);
                branch_type* new_branch = new branch_type(parent_prefix);
                branch_type* old_branch = new branch_type(old_child_prefix);
                for (auto child_node : static_cast<branch_type*>(node)->nodes) {
                    old_branch->nodes.push_back(child_node);
                }
                leaf_type* new_leaf = new leaf_type(new_child_prefix, val);
                new_branch->nodes.push_back(old_branch);
                new_branch->nodes.push_back(new_leaf);
                sort_nodes(new_branch);
                static_cast<branch_type*>(parent)->nodes[child_index] = new_branch;
                delete node;
            }
        }
        
        return true;
    }
    
    T find(std::string key, T &val)
    {
        // find nearest matching node
        trie_node *node = root_node, *parent = nullptr;
        size_t prefix_offset, key_offset, child_index;
        find_node_internal(key, node, parent, prefix_offset, key_offset, child_index);
        
        // exact match
        if (key.length() == key_offset) {
            if (node->get_type() == trie_node_type_leaf) {
                return static_cast<leaf_type*>(node)->val;
            } else if (node->get_type() == trie_node_type_branch) {
                branch_type *branch = static_cast<branch_type*>(node);
                // Check if first child node is sentinel ""
                // Note: depends on nodes being sorted
                if (branch->nodes.size() > 0 &&
                    branch->nodes[0]->get_type() == trie_node_type_leaf &&
                    branch->nodes[0]->prefix.size() == 0)
                {
                    return static_cast<leaf_type*>(branch->nodes[0])->val;
                }
            }
        }
        
        // not found
        return T(0);
    }

    T find_nearest(std::string key)
    {
        // find nearest matching node
        trie_node *node = root_node, *parent = nullptr;
        size_t prefix_offset, child_index, key_offset;
        std::vector<trie_node*> stack;
        find_node_internal(key, node, parent, prefix_offset, key_offset, child_index, &stack);
        
        // if we don't have a complete match, search up the tree for the nearest leaf
        if (node && key.length() < key_offset + node->prefix.length() - prefix_offset) {
            for (size_t i = stack.size(); i > 0; i--) {
                trie_node *node = stack[i - 1];
                if (node && node->get_type() == trie_node_type_branch) {
                    branch_type *branch = static_cast<branch_type*>(node);
                    // Check if first child node is sentinel ""
                    // Note: depends on nodes being sorted
                    if (branch->nodes.size() > 0 &&
                        branch->nodes[0]->get_type() == trie_node_type_leaf &&
                        branch->nodes[0]->prefix.size() == 0)
                    {
                        return static_cast<leaf_type*>(branch->nodes[0])->val;
                    }
                }
            }
            return T(0);
        }
        
        if (node->get_type() == trie_node_type_leaf) {
            return static_cast<leaf_type*>(node)->val;
        } else if (node->get_type() == trie_node_type_branch) {
            branch_type *branch = static_cast<branch_type*>(node);
            // Check if first child node is sentinel ""
            // Note: depends on nodes being sorted
            if (branch->nodes.size() > 0 &&
                branch->nodes[0]->get_type() == trie_node_type_leaf &&
                branch->nodes[0]->prefix.size() == 0)
            {
                return static_cast<leaf_type*>(branch->nodes[0])->val;
            }
        }
        
        // not found
        return T(0);
    }
};

#endif
