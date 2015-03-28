//
//  config_parser.h
//

#ifndef config_parser_h
#define config_parser_h

struct config_parser
{
    int cs;
    int eof;
    size_t mark;
    
    virtual ~config_parser() {}
    
    bool parse(const char *buffer, size_t len);
    
    virtual void symbol(const char *value, size_t length) = 0;
    virtual void end_statement() = 0;
    virtual void config_done() = 0;
};

#endif
