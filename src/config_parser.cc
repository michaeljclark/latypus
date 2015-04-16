
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


#line 40 "src/config_parser.rl"



#line 21 "src/config_parser.cc"
static const char _config_parser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 5, 2, 1, 0, 
	2, 1, 5, 2, 2, 0, 2, 2, 
	5, 2, 4, 0, 2, 4, 5
};

static const unsigned char _config_parser_key_offsets[] = {
	0, 0, 7, 15, 23, 30, 38, 46, 
	54, 63, 72, 77, 85, 93, 102, 103, 
	105, 111, 119, 128, 136, 145, 153, 161, 
	169, 177, 185, 193, 202, 211, 220, 229, 
	238
};

static const char _config_parser_trans_keys[] = {
	13, 32, 59, 123, 125, 9, 10, 13, 
	32, 47, 59, 123, 125, 9, 10, 13, 
	32, 42, 59, 123, 125, 9, 10, 13, 
	32, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 47, 59, 123, 125, 9, 10, 13, 
	32, 42, 47, 59, 123, 125, 9, 10, 
	13, 32, 59, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	47, 59, 123, 125, 9, 10, 42, 42, 
	47, 13, 32, 42, 59, 9, 10, 13, 
	32, 42, 59, 123, 125, 9, 10, 13, 
	32, 42, 47, 59, 123, 125, 9, 10, 
	13, 32, 42, 59, 123, 125, 9, 10, 
	13, 32, 42, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 47, 59, 123, 125, 9, 
	10, 13, 32, 42, 47, 59, 123, 125, 
	9, 10, 13, 32, 42, 47, 59, 123, 
	125, 9, 10, 13, 32, 42, 47, 59, 
	123, 125, 9, 10, 13, 32, 42, 47, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	47, 59, 123, 125, 9, 10, 13, 32, 
	42, 47, 59, 123, 125, 9, 10, 0
};

static const char _config_parser_single_lengths[] = {
	0, 5, 6, 6, 5, 6, 6, 6, 
	7, 7, 3, 6, 6, 7, 1, 2, 
	4, 6, 7, 6, 7, 6, 6, 6, 
	6, 6, 6, 7, 7, 7, 7, 7, 
	7
};

static const char _config_parser_range_lengths[] = {
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 0, 0, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1
};

static const short _config_parser_index_offsets[] = {
	0, 0, 7, 15, 23, 30, 38, 46, 
	54, 63, 72, 77, 85, 93, 102, 104, 
	107, 113, 121, 130, 138, 147, 155, 163, 
	171, 179, 187, 195, 204, 213, 222, 231, 
	240
};

static const char _config_parser_indicies[] = {
	1, 1, 2, 3, 3, 1, 0, 5, 
	5, 6, 7, 8, 3, 5, 4, 1, 
	1, 9, 2, 3, 3, 1, 0, 3, 
	3, 3, 3, 3, 3, 0, 1, 1, 
	10, 2, 3, 3, 1, 0, 12, 12, 
	13, 12, 12, 12, 12, 11, 14, 14, 
	13, 15, 12, 12, 14, 11, 17, 17, 
	18, 19, 20, 21, 12, 17, 16, 14, 
	14, 13, 22, 15, 12, 12, 14, 11, 
	23, 23, 24, 23, 3, 1, 1, 11, 
	2, 3, 3, 1, 0, 14, 14, 25, 
	15, 12, 12, 14, 11, 12, 12, 13, 
	26, 12, 12, 12, 12, 11, 27, 12, 
	27, 28, 12, 29, 29, 27, 30, 29, 
	12, 14, 14, 31, 15, 12, 12, 14, 
	11, 14, 14, 13, 26, 15, 12, 12, 
	14, 11, 14, 14, 32, 15, 12, 12, 
	14, 11, 12, 12, 13, 22, 12, 12, 
	12, 12, 11, 28, 28, 33, 3, 3, 
	23, 28, 4, 35, 35, 36, 3, 3, 
	37, 35, 34, 38, 38, 39, 2, 3, 
	23, 38, 4, 40, 40, 33, 7, 8, 
	23, 40, 4, 42, 42, 43, 3, 3, 
	44, 42, 41, 46, 46, 47, 3, 3, 
	48, 46, 45, 50, 50, 51, 52, 12, 
	12, 53, 50, 49, 54, 54, 18, 55, 
	12, 12, 29, 54, 16, 56, 56, 18, 
	57, 15, 12, 29, 56, 16, 58, 58, 
	18, 55, 20, 21, 29, 58, 16, 60, 
	60, 61, 62, 12, 12, 63, 60, 59, 
	65, 65, 66, 67, 12, 12, 68, 65, 
	64, 0
};

static const char _config_parser_trans_targs[] = {
	1, 2, 22, 0, 1, 2, 3, 22, 
	25, 4, 6, 7, 14, 9, 8, 27, 
	7, 8, 9, 19, 27, 31, 23, 10, 
	26, 13, 29, 15, 21, 16, 32, 18, 
	20, 5, 1, 21, 5, 10, 24, 11, 
	24, 1, 21, 5, 10, 1, 21, 5, 
	10, 7, 28, 9, 12, 16, 28, 12, 
	30, 17, 30, 7, 28, 9, 12, 16, 
	7, 28, 9, 12, 16
};

static const char _config_parser_trans_actions[] = {
	0, 7, 7, 0, 1, 0, 1, 0, 
	0, 0, 0, 0, 0, 0, 7, 7, 
	1, 0, 1, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 25, 9, 25, 9, 7, 1, 
	0, 13, 3, 13, 3, 19, 5, 19, 
	5, 25, 9, 25, 25, 9, 0, 1, 
	7, 1, 0, 13, 3, 13, 13, 3, 
	19, 5, 19, 19, 5
};

static const char _config_parser_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 11, 28, 11, 
	11, 16, 22, 28, 11, 11, 11, 16, 
	22
};

static const int config_parser_start = 21;
static const int config_parser_first_final = 21;
static const int config_parser_error = 0;

static const int config_parser_en_main = 21;


#line 43 "src/config_parser.rl"

bool config_parser::parse(const char *buffer, size_t len)
{
    int cs = config_parser_en_main;
    
    const char *mark = NULL;
    const char *p = buffer;
    const char *pe = buffer + strlen(buffer);
    const char *eof = pe;

    
#line 181 "src/config_parser.cc"
	{
	cs = config_parser_start;
	}

#line 54 "src/config_parser.rl"
    
#line 188 "src/config_parser.cc"
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
	{ start_block(); }
	break;
	case 2:
#line 19 "src/config_parser.rl"
	{ end_block(); }
	break;
	case 3:
#line 20 "src/config_parser.rl"
	{ symbol(mark, p - mark); }
	break;
	case 4:
#line 21 "src/config_parser.rl"
	{ end_statement(); }
	break;
#line 282 "src/config_parser.cc"
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
	case 1:
#line 18 "src/config_parser.rl"
	{ start_block(); }
	break;
	case 2:
#line 19 "src/config_parser.rl"
	{ end_block(); }
	break;
	case 4:
#line 21 "src/config_parser.rl"
	{ end_statement(); }
	break;
	case 5:
#line 23 "src/config_parser.rl"
	{ 
        config_done();
        {p++; goto _out; }
    }
	break;
#line 317 "src/config_parser.cc"
		}
	}
	}

	_out: {}
	}

#line 55 "src/config_parser.rl"

    return (cs != config_parser_error && cs == config_parser_first_final);
}
