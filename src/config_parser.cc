
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

static const short _config_parser_key_offsets[] = {
	0, 0, 7, 15, 22, 30, 38, 45, 
	53, 61, 69, 78, 86, 95, 104, 109, 
	117, 125, 134, 142, 150, 159, 160, 162, 
	168, 176, 185, 193, 202, 210, 218, 226, 
	234, 242, 250, 258, 266, 275, 284, 293, 
	302, 311
};

static const char _config_parser_trans_keys[] = {
	13, 32, 59, 123, 125, 9, 10, 13, 
	32, 47, 59, 123, 125, 9, 10, 13, 
	32, 59, 123, 125, 9, 10, 13, 32, 
	47, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	47, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 47, 59, 123, 125, 9, 10, 13, 
	32, 42, 47, 59, 123, 125, 9, 10, 
	13, 32, 59, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	47, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 59, 123, 125, 9, 10, 13, 32, 
	42, 47, 59, 123, 125, 9, 10, 42, 
	42, 47, 13, 32, 42, 59, 9, 10, 
	13, 32, 42, 59, 123, 125, 9, 10, 
	13, 32, 42, 47, 59, 123, 125, 9, 
	10, 13, 32, 42, 59, 123, 125, 9, 
	10, 13, 32, 42, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 47, 59, 123, 125, 
	9, 10, 13, 32, 42, 47, 59, 123, 
	125, 9, 10, 13, 32, 42, 47, 59, 
	123, 125, 9, 10, 13, 32, 42, 47, 
	59, 123, 125, 9, 10, 13, 32, 42, 
	47, 59, 123, 125, 9, 10, 13, 32, 
	42, 47, 59, 123, 125, 9, 10, 13, 
	32, 42, 47, 59, 123, 125, 9, 10, 
	0
};

static const char _config_parser_single_lengths[] = {
	0, 5, 6, 5, 6, 6, 5, 6, 
	6, 6, 7, 6, 7, 7, 3, 6, 
	6, 7, 6, 6, 7, 1, 2, 4, 
	6, 7, 6, 7, 6, 6, 6, 6, 
	6, 6, 6, 6, 7, 7, 7, 7, 
	7, 7
};

static const char _config_parser_range_lengths[] = {
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 0, 0, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1
};

static const short _config_parser_index_offsets[] = {
	0, 0, 7, 15, 22, 30, 38, 45, 
	53, 61, 69, 78, 86, 95, 104, 109, 
	117, 125, 134, 142, 150, 159, 161, 164, 
	170, 178, 187, 195, 204, 212, 220, 228, 
	236, 244, 252, 260, 268, 277, 286, 295, 
	304, 313
};

static const char _config_parser_indicies[] = {
	1, 1, 2, 3, 3, 1, 0, 5, 
	5, 6, 7, 8, 3, 5, 4, 10, 
	10, 2, 3, 3, 10, 9, 11, 11, 
	6, 7, 3, 3, 11, 4, 10, 10, 
	12, 2, 3, 3, 10, 9, 3, 3, 
	3, 3, 3, 3, 9, 1, 1, 13, 
	2, 3, 3, 1, 0, 15, 15, 16, 
	15, 15, 15, 15, 14, 17, 17, 16, 
	18, 15, 15, 17, 14, 20, 20, 21, 
	22, 23, 24, 15, 20, 19, 26, 26, 
	27, 18, 15, 15, 26, 25, 28, 28, 
	21, 22, 23, 15, 15, 28, 19, 26, 
	26, 27, 29, 18, 15, 15, 26, 25, 
	30, 30, 31, 30, 3, 1, 1, 32, 
	2, 3, 3, 1, 0, 26, 26, 16, 
	18, 15, 15, 26, 14, 17, 17, 16, 
	33, 18, 15, 15, 17, 14, 1, 1, 
	14, 2, 3, 3, 1, 0, 17, 17, 
	34, 18, 15, 15, 17, 14, 15, 15, 
	16, 35, 15, 15, 15, 15, 14, 36, 
	15, 36, 37, 15, 38, 38, 36, 39, 
	38, 15, 17, 17, 40, 18, 15, 15, 
	17, 14, 17, 17, 16, 35, 18, 15, 
	15, 17, 14, 26, 26, 41, 18, 15, 
	15, 26, 25, 15, 15, 27, 29, 15, 
	15, 15, 15, 25, 37, 37, 43, 3, 
	3, 30, 37, 42, 45, 45, 46, 3, 
	3, 47, 45, 44, 48, 48, 49, 2, 
	3, 30, 48, 42, 50, 50, 43, 7, 
	3, 30, 50, 42, 52, 52, 53, 3, 
	3, 54, 52, 51, 55, 55, 56, 2, 
	3, 30, 55, 42, 57, 57, 43, 7, 
	8, 30, 57, 42, 59, 59, 60, 3, 
	3, 61, 59, 58, 63, 63, 64, 65, 
	15, 15, 66, 63, 62, 68, 68, 69, 
	70, 15, 15, 38, 68, 67, 71, 71, 
	69, 72, 18, 15, 38, 71, 67, 73, 
	73, 69, 70, 23, 24, 38, 73, 67, 
	75, 75, 76, 77, 15, 15, 78, 75, 
	74, 80, 80, 81, 82, 15, 15, 83, 
	80, 79, 0
};

static const char _config_parser_trans_targs[] = {
	1, 2, 29, 0, 3, 2, 5, 29, 
	35, 3, 4, 4, 6, 8, 9, 21, 
	17, 10, 36, 11, 10, 13, 26, 36, 
	40, 11, 12, 13, 12, 30, 14, 32, 
	16, 33, 20, 38, 22, 28, 23, 41, 
	25, 27, 1, 7, 1, 28, 7, 14, 
	31, 15, 31, 1, 28, 7, 14, 34, 
	18, 34, 1, 28, 7, 14, 9, 37, 
	17, 19, 23, 9, 37, 17, 19, 39, 
	24, 39, 9, 37, 17, 19, 23, 9, 
	37, 17, 19, 23
};

static const char _config_parser_trans_actions[] = {
	0, 7, 7, 0, 1, 0, 1, 0, 
	0, 0, 7, 0, 0, 0, 0, 0, 
	0, 7, 7, 1, 0, 1, 1, 0, 
	0, 0, 7, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 25, 9, 25, 9, 
	7, 1, 0, 19, 5, 19, 5, 7, 
	1, 0, 13, 3, 13, 3, 25, 9, 
	25, 25, 9, 1, 0, 1, 1, 7, 
	1, 0, 13, 3, 13, 13, 3, 19, 
	5, 19, 19, 5
};

static const char _config_parser_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 11, 28, 11, 11, 
	22, 11, 11, 16, 28, 11, 11, 11, 
	16, 22
};

static const int config_parser_start = 28;
static const int config_parser_first_final = 28;
static const int config_parser_error = 0;

static const int config_parser_en_main = 28;


#line 43 "src/config_parser.rl"

bool config_parser::parse(const char *buffer, size_t len)
{
    int cs = config_parser_en_main;
    
    const char *mark = NULL;
    const char *p = buffer;
    const char *pe = buffer + strlen(buffer);
    const char *eof = pe;

    
#line 209 "src/config_parser.cc"
	{
	cs = config_parser_start;
	}

#line 54 "src/config_parser.rl"
    
#line 216 "src/config_parser.cc"
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
#line 310 "src/config_parser.cc"
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
#line 345 "src/config_parser.cc"
		}
	}
	}

	_out: {}
	}

#line 55 "src/config_parser.rl"

    return (cs != config_parser_error && cs == config_parser_first_final);
}
