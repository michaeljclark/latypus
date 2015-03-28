
#line 1 "src/config_parser.rl"
//
//  config_parser.rl
//

#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <ctype.h>
#include <cstring>

#include "config_parser.h"


#line 35 "src/config_parser.rl"



#line 21 "src/config_parser.cc"
static const char _config_parser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 2, 2, 0, 2, 2, 3
};

static const char _config_parser_key_offsets[] = {
	0, 0, 5, 11, 17, 22, 28, 34, 
	40, 47, 54, 60, 66, 73, 74, 76, 
	82, 89, 95, 101, 107, 113, 120
};

static const char _config_parser_trans_keys[] = {
	13, 32, 59, 9, 10, 13, 32, 47, 
	59, 9, 10, 13, 32, 42, 59, 9, 
	10, 13, 32, 59, 9, 10, 13, 32, 
	42, 59, 9, 10, 13, 32, 42, 59, 
	9, 10, 13, 32, 42, 59, 9, 10, 
	13, 32, 42, 47, 59, 9, 10, 13, 
	32, 42, 47, 59, 9, 10, 13, 32, 
	42, 59, 9, 10, 13, 32, 42, 59, 
	9, 10, 13, 32, 42, 47, 59, 9, 
	10, 42, 42, 47, 13, 32, 42, 59, 
	9, 10, 13, 32, 42, 47, 59, 9, 
	10, 13, 32, 47, 59, 9, 10, 13, 
	32, 47, 59, 9, 10, 13, 32, 47, 
	59, 9, 10, 13, 32, 47, 59, 9, 
	10, 13, 32, 42, 47, 59, 9, 10, 
	13, 32, 42, 47, 59, 9, 10, 0
};

static const char _config_parser_single_lengths[] = {
	0, 3, 4, 4, 3, 4, 4, 4, 
	5, 5, 4, 4, 5, 1, 2, 4, 
	5, 4, 4, 4, 4, 5, 5
};

static const char _config_parser_range_lengths[] = {
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 0, 0, 1, 
	1, 1, 1, 1, 1, 1, 1
};

static const unsigned char _config_parser_index_offsets[] = {
	0, 0, 5, 11, 17, 22, 28, 34, 
	40, 47, 54, 60, 66, 73, 75, 78, 
	84, 91, 97, 103, 109, 115, 122
};

static const char _config_parser_indicies[] = {
	1, 1, 2, 1, 0, 4, 4, 5, 
	6, 4, 3, 1, 1, 7, 2, 1, 
	0, 8, 8, 8, 8, 0, 1, 1, 
	9, 2, 1, 0, 11, 11, 12, 11, 
	11, 10, 13, 13, 12, 14, 13, 10, 
	16, 16, 17, 18, 19, 16, 15, 13, 
	13, 12, 20, 14, 13, 10, 1, 1, 
	10, 2, 1, 0, 13, 13, 21, 14, 
	13, 10, 11, 11, 12, 22, 11, 11, 
	10, 23, 11, 23, 22, 11, 13, 13, 
	24, 14, 13, 10, 11, 11, 12, 20, 
	11, 11, 10, 22, 22, 25, 8, 22, 
	3, 27, 27, 28, 8, 27, 26, 29, 
	29, 30, 2, 29, 3, 31, 31, 25, 
	6, 31, 3, 33, 33, 34, 35, 11, 
	33, 32, 36, 36, 17, 37, 11, 36, 
	15, 0
};

static const char _config_parser_trans_targs[] = {
	1, 2, 18, 1, 2, 3, 18, 4, 
	0, 6, 7, 13, 9, 8, 21, 7, 
	8, 9, 15, 21, 19, 12, 17, 14, 
	16, 5, 1, 17, 5, 20, 10, 20, 
	7, 22, 9, 11, 22, 11
};

static const char _config_parser_trans_actions[] = {
	0, 3, 3, 1, 0, 1, 0, 0, 
	0, 0, 0, 0, 0, 3, 3, 1, 
	0, 1, 1, 0, 0, 0, 0, 0, 
	0, 1, 9, 5, 9, 3, 1, 0, 
	9, 5, 9, 9, 0, 1
};

static const char _config_parser_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 7, 12, 7, 7, 12, 7
};

static const int config_parser_start = 17;
static const int config_parser_first_final = 17;
static const int config_parser_error = 0;

static const int config_parser_en_main = 17;


#line 38 "src/config_parser.rl"

bool config_parser::parse(const char *buffer, size_t len)
{
    int cs = config_parser_en_main;
    
    const char *mark = NULL;
    const char *p = buffer;
    const char *pe = buffer + strlen(buffer);
    const char *eof = pe;

    
#line 131 "src/config_parser.cc"
	{
	cs = config_parser_start;
	}

#line 49 "src/config_parser.rl"
    
#line 138 "src/config_parser.cc"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _config_parser_trans_keys + _config_parser_key_offsets[cs];
	_trans = _config_parser_index_offsets[cs];

	_klen = _config_parser_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _config_parser_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _config_parser_indicies[_trans];
	cs = _config_parser_trans_targs[_trans];

	if ( _config_parser_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _config_parser_actions + _config_parser_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 17 "src/config_parser.rl"
	{ mark = p; }
	break;
	case 1:
#line 18 "src/config_parser.rl"
	{ symbol(mark, p - mark); }
	break;
	case 2:
#line 19 "src/config_parser.rl"
	{ end_statement(); }
	break;
#line 224 "src/config_parser.cc"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _config_parser_actions + _config_parser_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 2:
#line 19 "src/config_parser.rl"
	{ end_statement(); }
	break;
	case 3:
#line 21 "src/config_parser.rl"
	{ 
        config_done();
        {p++; goto _out; }
    }
	break;
#line 251 "src/config_parser.cc"
		}
	}
	}

	_out: {}
	}

#line 50 "src/config_parser.rl"

    return (cs != config_parser_error && cs == config_parser_first_final);
}
