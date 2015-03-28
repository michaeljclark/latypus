//
//  config_parser.rl
//

#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <ctype.h>
#include <cstring>

#include "config_parser.h"

%%{
    
    machine config_parser;

    action mark             { mark = fpc; }
    action write_symbol     { symbol(mark, fpc - mark); }
    action end_statement    { end_statement(); }

    action done { 
        config_done();
        fbreak;
    }

    Eol = ';' %end_statement;
    WhiteSpace = (' ' | '\t' | '\r' | '\n' )+;
    Comment = ( '/*' any* :>> '*/' );
    Symbol = ( ( any - WhiteSpace - ';' )+ - ('/*') ) >mark %write_symbol;
    Statement = ( Symbol ( WhiteSpace Symbol)* ) WhiteSpace* Eol;
    Config = ( Comment | Statement | WhiteSpace)* %done;

    main := Config;

}%%

%% write data;

bool config_parser::parse(const char *buffer, size_t len)
{
    int cs = config_parser_en_main;
    
    const char *mark = NULL;
    const char *p = buffer;
    const char *pe = buffer + strlen(buffer);
    const char *eof = pe;

    %% write init;
    %% write exec;

    return (cs != config_parser_error && cs == config_parser_first_final);
}
