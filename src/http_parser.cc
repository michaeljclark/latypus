
#line 1 "src/http_parser.rl"
/*
 * derived from mongrel/http11_parser.rl
 *
 * Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */

#include <cstring>
#include <sstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <map>

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"


#line 89 "src/http_parser.rl"



#line 22 "src/http_parser.cc"
static const char _http_parser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 5, 1, 6, 1, 
	7, 1, 8, 1, 10, 1, 11, 1, 
	12, 1, 13, 1, 14, 1, 15, 1, 
	16, 2, 0, 8, 2, 3, 5, 2, 
	9, 7, 2, 11, 7, 2, 14, 1, 
	2, 14, 16, 2, 15, 1, 2, 15, 
	16, 3, 4, 9, 7
};

static const short _http_parser_key_offsets[] = {
	0, 0, 9, 18, 28, 30, 31, 32, 
	33, 34, 35, 37, 40, 42, 46, 63, 
	64, 80, 83, 85, 102, 103, 104, 110, 
	116, 122, 128, 138, 144, 150, 156, 164, 
	170, 176, 182, 188, 194, 200, 209, 218, 
	227, 236, 245, 254, 263, 272, 281, 290, 
	299, 308, 317, 326, 335, 344, 353, 362, 
	363, 373, 383, 393, 401, 403, 406, 408, 
	411, 413, 415, 417, 418, 419, 421, 438
};

static const char _http_parser_trans_keys[] = {
	36, 72, 95, 45, 46, 48, 57, 65, 
	90, 32, 36, 95, 45, 46, 48, 57, 
	65, 90, 42, 43, 47, 58, 45, 57, 
	65, 90, 97, 122, 32, 35, 72, 84, 
	84, 80, 47, 48, 57, 46, 48, 57, 
	48, 57, 10, 13, 48, 57, 10, 13, 
	33, 124, 126, 35, 39, 42, 43, 45, 
	46, 48, 57, 65, 90, 94, 122, 10, 
	33, 58, 124, 126, 35, 39, 42, 43, 
	45, 46, 48, 57, 65, 90, 94, 122, 
	10, 13, 32, 10, 13, 10, 13, 33, 
	124, 126, 35, 39, 42, 43, 45, 46, 
	48, 57, 65, 90, 94, 122, 10, 10, 
	32, 35, 37, 127, 0, 31, 32, 35, 
	37, 127, 0, 31, 48, 57, 65, 70, 
	97, 102, 48, 57, 65, 70, 97, 102, 
	43, 58, 45, 46, 48, 57, 65, 90, 
	97, 122, 32, 35, 37, 127, 0, 31, 
	48, 57, 65, 70, 97, 102, 48, 57, 
	65, 70, 97, 102, 32, 35, 37, 59, 
	63, 127, 0, 31, 48, 57, 65, 70, 
	97, 102, 48, 57, 65, 70, 97, 102, 
	32, 35, 37, 127, 0, 31, 32, 35, 
	37, 127, 0, 31, 48, 57, 65, 70, 
	97, 102, 48, 57, 65, 70, 97, 102, 
	32, 36, 95, 45, 46, 48, 57, 65, 
	90, 32, 36, 95, 45, 46, 48, 57, 
	65, 90, 32, 36, 95, 45, 46, 48, 
	57, 65, 90, 32, 36, 95, 45, 46, 
	48, 57, 65, 90, 32, 36, 95, 45, 
	46, 48, 57, 65, 90, 32, 36, 95, 
	45, 46, 48, 57, 65, 90, 32, 36, 
	95, 45, 46, 48, 57, 65, 90, 32, 
	36, 95, 45, 46, 48, 57, 65, 90, 
	32, 36, 95, 45, 46, 48, 57, 65, 
	90, 32, 36, 95, 45, 46, 48, 57, 
	65, 90, 32, 36, 95, 45, 46, 48, 
	57, 65, 90, 32, 36, 95, 45, 46, 
	48, 57, 65, 90, 32, 36, 95, 45, 
	46, 48, 57, 65, 90, 32, 36, 95, 
	45, 46, 48, 57, 65, 90, 32, 36, 
	95, 45, 46, 48, 57, 65, 90, 32, 
	36, 95, 45, 46, 48, 57, 65, 90, 
	32, 36, 95, 45, 46, 48, 57, 65, 
	90, 32, 36, 95, 45, 46, 48, 57, 
	65, 90, 32, 32, 36, 84, 95, 45, 
	46, 48, 57, 65, 90, 32, 36, 84, 
	95, 45, 46, 48, 57, 65, 90, 32, 
	36, 80, 95, 45, 46, 48, 57, 65, 
	90, 32, 36, 47, 95, 45, 57, 65, 
	90, 48, 57, 46, 48, 57, 48, 57, 
	32, 48, 57, 48, 57, 48, 57, 48, 
	57, 32, 10, 10, 13, 10, 13, 33, 
	124, 126, 35, 39, 42, 43, 45, 46, 
	48, 57, 65, 90, 94, 122, 0
};

static const char _http_parser_single_lengths[] = {
	0, 3, 3, 4, 2, 1, 1, 1, 
	1, 1, 0, 1, 0, 2, 5, 1, 
	4, 3, 2, 5, 1, 1, 4, 4, 
	0, 0, 2, 4, 0, 0, 6, 0, 
	0, 4, 4, 0, 0, 3, 3, 3, 
	3, 3, 3, 3, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 3, 3, 1, 
	4, 4, 4, 4, 0, 1, 0, 1, 
	0, 0, 0, 1, 1, 2, 5, 0
};

static const char _http_parser_range_lengths[] = {
	0, 3, 3, 3, 0, 0, 0, 0, 
	0, 0, 1, 1, 1, 1, 6, 0, 
	6, 0, 0, 6, 0, 0, 1, 1, 
	3, 3, 4, 1, 3, 3, 1, 3, 
	3, 1, 1, 3, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 3, 3, 0, 
	3, 3, 3, 2, 1, 1, 1, 1, 
	1, 1, 1, 0, 0, 0, 6, 0
};

static const short _http_parser_index_offsets[] = {
	0, 0, 7, 14, 22, 25, 27, 29, 
	31, 33, 35, 37, 40, 42, 46, 58, 
	60, 71, 75, 78, 90, 92, 94, 100, 
	106, 110, 114, 121, 127, 131, 135, 143, 
	147, 151, 157, 163, 167, 171, 178, 185, 
	192, 199, 206, 213, 220, 227, 234, 241, 
	248, 255, 262, 269, 276, 283, 290, 297, 
	299, 307, 315, 323, 330, 332, 335, 337, 
	340, 342, 344, 346, 348, 350, 353, 365
};

static const char _http_parser_indicies[] = {
	0, 2, 0, 0, 0, 0, 1, 3, 
	4, 4, 4, 4, 4, 1, 5, 6, 
	7, 8, 6, 6, 6, 1, 9, 10, 
	1, 11, 1, 12, 1, 13, 1, 14, 
	1, 15, 1, 16, 1, 17, 16, 1, 
	18, 1, 19, 20, 18, 1, 21, 22, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 1, 24, 1, 25, 26, 25, 25, 
	25, 25, 25, 25, 25, 25, 1, 28, 
	29, 30, 27, 32, 33, 31, 24, 34, 
	35, 35, 35, 35, 35, 35, 35, 35, 
	35, 1, 36, 1, 37, 1, 39, 1, 
	40, 1, 1, 38, 42, 1, 43, 1, 
	1, 41, 44, 44, 44, 1, 41, 41, 
	41, 1, 45, 46, 45, 45, 45, 45, 
	1, 9, 10, 47, 1, 1, 46, 48, 
	48, 48, 1, 46, 46, 46, 1, 50, 
	51, 52, 1, 53, 1, 1, 49, 54, 
	54, 54, 1, 49, 49, 49, 1, 56, 
	57, 58, 1, 1, 55, 60, 61, 62, 
	1, 1, 59, 63, 63, 63, 1, 59, 
	59, 59, 1, 3, 64, 64, 64, 64, 
	64, 1, 3, 65, 65, 65, 65, 65, 
	1, 3, 66, 66, 66, 66, 66, 1, 
	3, 67, 67, 67, 67, 67, 1, 3, 
	68, 68, 68, 68, 68, 1, 3, 69, 
	69, 69, 69, 69, 1, 3, 70, 70, 
	70, 70, 70, 1, 3, 71, 71, 71, 
	71, 71, 1, 3, 72, 72, 72, 72, 
	72, 1, 3, 73, 73, 73, 73, 73, 
	1, 3, 74, 74, 74, 74, 74, 1, 
	3, 75, 75, 75, 75, 75, 1, 3, 
	76, 76, 76, 76, 76, 1, 3, 77, 
	77, 77, 77, 77, 1, 3, 78, 78, 
	78, 78, 78, 1, 3, 79, 79, 79, 
	79, 79, 1, 3, 80, 80, 80, 80, 
	80, 1, 3, 81, 81, 81, 81, 81, 
	1, 3, 1, 3, 4, 82, 4, 4, 
	4, 4, 1, 3, 64, 83, 64, 64, 
	64, 64, 1, 3, 65, 84, 65, 65, 
	65, 65, 1, 3, 66, 85, 66, 66, 
	66, 1, 86, 1, 87, 86, 1, 88, 
	1, 89, 88, 1, 90, 1, 91, 1, 
	92, 1, 93, 1, 1, 94, 96, 97, 
	95, 98, 99, 100, 100, 100, 100, 100, 
	100, 100, 100, 100, 1, 1, 0
};

static const char _http_parser_trans_targs[] = {
	2, 0, 56, 3, 37, 4, 26, 30, 
	27, 5, 22, 6, 7, 8, 9, 10, 
	11, 12, 13, 14, 21, 71, 15, 16, 
	71, 16, 17, 18, 19, 20, 17, 18, 
	19, 20, 15, 16, 19, 14, 23, 5, 
	24, 23, 5, 24, 25, 26, 27, 28, 
	29, 30, 5, 22, 31, 33, 32, 34, 
	5, 22, 35, 34, 5, 22, 35, 36, 
	38, 39, 40, 41, 42, 43, 44, 45, 
	46, 47, 48, 49, 50, 51, 52, 53, 
	54, 55, 57, 58, 59, 60, 61, 62, 
	63, 64, 65, 66, 67, 68, 69, 69, 
	70, 69, 71, 15, 16
};

static const char _http_parser_trans_actions[] = {
	1, 0, 1, 13, 0, 1, 1, 1, 
	1, 15, 15, 1, 0, 0, 0, 0, 
	0, 0, 0, 19, 19, 54, 29, 51, 
	31, 0, 5, 7, 36, 36, 7, 0, 
	11, 11, 0, 3, 0, 0, 1, 33, 
	1, 0, 17, 0, 0, 0, 0, 0, 
	0, 0, 42, 42, 0, 21, 0, 9, 
	57, 57, 9, 0, 39, 39, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 19, 1, 0, 0, 23, 1, 0, 
	25, 25, 48, 27, 45
};

static const int http_parser_start = 1;
static const int http_parser_first_final = 71;
static const int http_parser_error = 0;

static const int http_parser_en_main = 1;


#line 92 "src/http_parser.rl"

http_parser::http_parser() {}
http_parser::~http_parser() {}

void http_parser::reset()
{
    
#line 236 "src/http_parser.cc"
	{
	cs = http_parser_start;
	}

#line 99 "src/http_parser.rl"
    
    nread = 0;
    mark = NULL;
    query_start = NULL;
    field_start = NULL;
    field_len = 0;
    cs = http_parser_en_main;
}

size_t http_parser::parse(const char *buf, size_t len)
{
    const char *p = buf;
    const char *pe = buf + len;

    
#line 257 "src/http_parser.cc"
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
	_keys = _http_parser_trans_keys + _http_parser_key_offsets[cs];
	_trans = _http_parser_index_offsets[cs];

	_klen = _http_parser_single_lengths[cs];
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

	_klen = _http_parser_range_lengths[cs];
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
	_trans = _http_parser_indicies[_trans];
	cs = _http_parser_trans_targs[_trans];

	if ( _http_parser_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _http_parser_actions + _http_parser_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 18 "src/http_parser.rl"
	{ mark = p; }
	break;
	case 1:
#line 19 "src/http_parser.rl"
	{ field_start = p; }
	break;
	case 2:
#line 20 "src/http_parser.rl"
	{ field_len = p - field_start; }
	break;
	case 3:
#line 21 "src/http_parser.rl"
	{ mark = p; }
	break;
	case 4:
#line 22 "src/http_parser.rl"
	{ query_start = p; }
	break;
	case 5:
#line 23 "src/http_parser.rl"
	{ set_header_field(http_header_string(field_start, field_len), http_header_string(mark, p - mark)); }
	break;
	case 6:
#line 24 "src/http_parser.rl"
	{ set_request_method(http_header_string(mark, p - mark)); }
	break;
	case 7:
#line 25 "src/http_parser.rl"
	{ set_request_uri(http_header_string(mark, p - mark)); }
	break;
	case 8:
#line 26 "src/http_parser.rl"
	{ set_fragment(http_header_string(mark, p - mark)); }
	break;
	case 9:
#line 27 "src/http_parser.rl"
	{ set_query_string(http_header_string(query_start, p - query_start)); }
	break;
	case 10:
#line 28 "src/http_parser.rl"
	{ set_http_version(http_header_string(mark, p - mark)); }
	break;
	case 11:
#line 29 "src/http_parser.rl"
	{ set_request_path(http_header_string(mark, p - mark)); }
	break;
	case 12:
#line 30 "src/http_parser.rl"
	{ set_status_code(atoi(std::string(mark, p - mark).c_str())); }
	break;
	case 13:
#line 31 "src/http_parser.rl"
	{ set_reason_phrase(http_header_string(mark, p - mark)); }
	break;
	case 14:
#line 32 "src/http_parser.rl"
	{ set_parse_type(http_parse_response); }
	break;
	case 15:
#line 33 "src/http_parser.rl"
	{ set_parse_type(http_parse_request); }
	break;
	case 16:
#line 34 "src/http_parser.rl"
	{ set_body_start(http_header_string(p + 1, len - (p + 1 - buf))); {p++; goto _out; } }
	break;
#line 399 "src/http_parser.cc"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 114 "src/http_parser.rl"

    nread += p - buf;

    return nread;
}

bool http_parser::has_error() { return (cs == http_parser_error); }
bool http_parser::is_finished() { return (cs == http_parser_first_final); }
size_t http_parser::bytes_read() { return nread; }
