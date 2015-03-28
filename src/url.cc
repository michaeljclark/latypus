//
//  url.cc
//

#include <memory>
#include <deque>
#include <sstream>
#include <string>

#include "url.h"

url::url(std::string url_string) : port(0), valid(false)
{
    size_t scheme_pos = url_string.find("://");
    if (scheme_pos == std::string::npos) {
        return;
    }
    scheme = url_string.substr(0, scheme_pos);
    std::string host_port_path = url_string.substr(scheme_pos + 3);
    size_t host_port_pos = host_port_path.find('/');
    if (host_port_pos == std::string::npos) {
        return;
    }
    std::string host_port = host_port_path.substr(0, host_port_pos);
    path = host_port_path.substr(host_port_pos);
    size_t host_colon_pos = host_port.find_last_of(':');
    if (host_colon_pos == std::string::npos) {
        host = host_port;
        if (scheme == "http") {
            port = 80;
        } else if (scheme == "https") {
            port = 443;
        } else {
            port = 0;
        }
    } else {
        host = host_port.substr(0, host_colon_pos);
        port = atoi(host_port.substr(host_colon_pos + 1).c_str());
    }
    valid = true;
}

bool url::is_valid() { return valid; }

std::string url::to_string()
{
    std::stringstream ss;
    if (valid) {
        ss << scheme << "://" << host;
        if (!((scheme == "http" && port == 80) || (scheme == "https" && port == 443))) {
            ss << ":" << port;
        }
        ss << path;
    }
    return ss.str();
}
