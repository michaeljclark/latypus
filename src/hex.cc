//
//  hex.cc
//

#include <cstdlib>
#include <string>

#include "hex.h"

const char* hex::HEX_DIGITS = "0123456789ABCDEF";

std::string hex::encode(const unsigned char *buf, size_t len)
{
    std::string hex;
    for (size_t i = 0; i < len; i++) {
        unsigned char b = buf[i];
        hex.append(HEX_DIGITS + ((b >> 4) & 0x0F), 1);
        hex.append(HEX_DIGITS + (b & 0x0F), 1);
    }
    return hex;
}

void hex::decode(std::string hex, unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < hex.length()/2 && i < len; i++) {
        const char tmp[3] = { hex[i*2], hex[i*2+1], 0 };
        *buf++ = (unsigned char)strtoul(tmp, NULL, 16);
    }
}
