//
//  hex.h
//

#ifndef hex_h
#define hex_h

struct hex
{
    static const char* HEX_DIGITS;
    
    static std::string encode(const unsigned char *buf, size_t len);
    static void decode(std::string hex, unsigned char *buf, size_t len);
};

#endif
