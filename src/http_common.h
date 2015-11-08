//
//  http_common.h
//

#ifndef http_common_h
#define http_common_h

struct http_header_string;
typedef std::pair<http_header_string,http_header_string> http_header_name_value;
typedef std::vector<http_header_name_value> http_header_list;
typedef std::map<http_header_string,http_header_string> http_header_map;


/* http_header_string */

struct http_header_string
{
    const char* data;
    size_t length;
    
    http_header_string() : data(NULL), length(0) {}
    http_header_string(const std::string &str) : data(str.c_str()), length(str.size()) {}
    http_header_string(const char* data) : data(data), length(strlen(data)) {}
    http_header_string(const char* data, size_t length) : data(data), length(length) {}
    
    int compare(const http_header_string &o) const
    {
        for (size_t i = 0; i < length && i < o.length; i++) {
            char c = data[i], oc = o.data[i];
            if (c < oc) return -1;
            if (c > oc) return 1;
        }
        return (length < o.length) ? -1 : (length > o.length) ? 1 : 0;
    }
    
    inline bool operator==(const http_header_string &o) const { return (compare(o) == 0); }
    inline bool operator!=(const http_header_string &o) const { return (compare(o) != 0); }
    inline bool operator<(const http_header_string &o) const { return (compare(o) < 0); }
    inline bool operator<=(const http_header_string &o) const { return (compare(o) <= 0); }
    inline bool operator>(const http_header_string &o) const {return (compare(o) > 0); }
    inline bool operator>=(const http_header_string &o) const {return (compare(o) >= 0); }
};

/*
namespace std {
    
    template <>
    struct hash<http_header_string>
    {
        std::size_t operator()(const http_header_string& hs) const
        {
            return std::hash<std::string>()(std::string(hs.data, hs.length));
        }
    };
    
}
*/

struct http_common
{
    static int sanitize_path(char *s);
};

#endif
