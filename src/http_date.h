//
//  http_date.h
//

#ifndef http_date_h
#define http_date_h

enum http_date_format
{
    http_date_format_header,
    http_date_format_log,
    http_date_format_iso,
};

struct http_date
{
    static const char* day_names[];
    static const char* month_names[];
    static const char* date_format;
    
    time_t tod;
    
    http_date();
    http_date(time_t tod);
    http_date(const char* str);
    http_date(const http_date &o);
    
    bool parse(const char *str);
    http_header_string to_header_string(char *buf, size_t buf_len);
    http_header_string to_log_string(char *buf, size_t buf_len);
    http_header_string to_iso_string(char *buf, size_t buf_len);
    std::string to_string(http_date_format fmt = http_date_format_header);
};

#endif
