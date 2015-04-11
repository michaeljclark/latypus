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
    action w_start_block    { start_block(); }
    action w_end_block      { end_block(); }
    action w_symbol         { symbol(mark, fpc - mark); }
    action w_end_statement  { end_statement(); }

    action done { 
        config_done();
        fbreak;
    }

    Eol = ';' %w_end_statement;
    newline = ('\r' | '\n' ) | '\n';
    ws = (' ' | '\t' | '\r' | '\n' )+;
    comment = '/*' ( any* - ( any* '*/' any* ) ) '*/';
    symbol = ( ( any - ';' - ws - '{' - '}' )+ - ('/*') ) >mark %w_symbol;
    statement = ( symbol ( ws symbol)* ) ws* Eol;
    end_block = symbol ws+ '{' %w_start_block;
    start_block = '}' ws* ';' %w_end_block;
    config = ( comment | start_block | end_block | statement | ws )* %done;

    main := config;

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
