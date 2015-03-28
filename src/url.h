//
//  url.h
//

#ifndef url_h
#define url_h

struct url;
typedef std::shared_ptr<url> url_ptr;

struct url
{
    std::string scheme;
    std::string host;
    std::string path;
    int port;
    bool valid;
    
    url(std::string url_string);
    
    bool is_valid();
    std::string to_string();
};

#endif
