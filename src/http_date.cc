
#line 1 "src/http_date.rl"
//
//  http_date.rl
//

#include <cstring>
#include <ctime>
#include <cstdlib>
#include <string>
#include <map>
#include <vector>

#include "http_common.h"
#include "http_date.h"


#line 64 "src/http_date.rl"



#line 23 "src/http_date.cc"
static const char _http_date_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	3, 1, 4, 1, 5, 1, 6, 1, 
	7, 1, 8, 1, 9, 1, 10, 1, 
	11, 1, 12, 1, 13, 1, 14, 1, 
	15, 1, 16, 1, 17, 1, 18, 1, 
	19, 1, 20, 1, 21, 1, 22, 1, 
	23, 1, 24, 1, 25, 1, 26, 2, 
	25, 1
};

static const short _http_date_key_offsets[] = {
	0, 0, 5, 6, 7, 12, 23, 25, 
	26, 29, 34, 39, 44, 46, 47, 49, 
	51, 52, 54, 56, 59, 64, 66, 68, 
	70, 73, 74, 77, 78, 79, 82, 83, 
	84, 87, 89, 90, 93, 95, 98, 101, 
	102, 104, 107, 110, 111, 112, 115, 116, 
	117, 120, 121, 122, 125, 128, 133, 139, 
	150, 152, 153, 156, 161, 163, 165, 167, 
	170, 175, 177, 178, 180, 182, 183, 185, 
	187, 190, 194, 195, 196, 197, 200, 201, 
	202, 205, 206, 207, 210, 212, 213, 216, 
	218, 221, 224, 225, 227, 230, 233, 234, 
	235, 238, 239, 240, 243, 244, 245, 248, 
	256, 258, 259, 260, 262, 264, 267, 268, 
	269, 270, 271, 272, 273, 274, 275, 277, 
	278, 279, 281, 282, 283, 284, 286, 287, 
	288, 289, 290, 291, 292, 293, 294, 295, 
	296, 297, 301, 302, 303, 307, 308, 309, 
	314, 315, 316, 320, 322, 323, 328, 329, 
	330, 331, 332, 336, 337, 342, 343, 344, 
	348, 350, 351, 356, 357, 358, 359, 360, 
	364, 365, 370, 371, 372, 373, 377, 378, 
	379, 384, 385, 386, 387, 388, 389, 393, 
	393
};

static const char _http_date_trans_keys[] = {
	70, 77, 83, 84, 87, 114, 105, 32, 
	44, 100, 9, 13, 32, 65, 68, 70, 
	74, 77, 78, 79, 83, 9, 13, 112, 
	117, 114, 32, 9, 13, 32, 9, 13, 
	48, 57, 32, 9, 13, 48, 57, 32, 
	9, 13, 48, 57, 48, 57, 58, 48, 
	57, 48, 57, 58, 48, 57, 48, 57, 
	32, 9, 13, 32, 9, 13, 48, 57, 
	48, 57, 48, 57, 48, 57, 32, 9, 
	13, 103, 32, 9, 13, 101, 99, 32, 
	9, 13, 101, 98, 32, 9, 13, 97, 
	117, 110, 32, 9, 13, 108, 110, 32, 
	9, 13, 32, 9, 13, 97, 114, 121, 
	32, 9, 13, 32, 9, 13, 111, 118, 
	32, 9, 13, 99, 116, 32, 9, 13, 
	101, 112, 32, 9, 13, 32, 9, 13, 
	32, 9, 13, 48, 57, 32, 45, 9, 
	13, 48, 57, 32, 65, 68, 70, 74, 
	77, 78, 79, 83, 9, 13, 112, 117, 
	114, 32, 9, 13, 32, 9, 13, 48, 
	57, 48, 57, 48, 57, 48, 57, 32, 
	9, 13, 32, 9, 13, 48, 57, 48, 
	57, 58, 48, 57, 48, 57, 58, 48, 
	57, 48, 57, 32, 9, 13, 32, 71, 
	9, 13, 77, 84, 103, 32, 9, 13, 
	101, 99, 32, 9, 13, 101, 98, 32, 
	9, 13, 97, 117, 110, 32, 9, 13, 
	108, 110, 32, 9, 13, 32, 9, 13, 
	97, 114, 121, 32, 9, 13, 32, 9, 
	13, 111, 118, 32, 9, 13, 99, 116, 
	32, 9, 13, 101, 112, 32, 9, 13, 
	65, 68, 70, 74, 77, 78, 79, 83, 
	112, 117, 114, 45, 48, 57, 48, 57, 
	32, 9, 13, 103, 45, 101, 99, 45, 
	101, 98, 45, 97, 117, 110, 45, 108, 
	110, 45, 45, 97, 114, 121, 45, 45, 
	111, 118, 45, 99, 116, 45, 101, 112, 
	45, 32, 45, 9, 13, 97, 121, 32, 
	44, 9, 13, 111, 110, 32, 44, 100, 
	9, 13, 97, 121, 32, 44, 9, 13, 
	97, 117, 116, 32, 44, 117, 9, 13, 
	114, 100, 97, 121, 32, 44, 9, 13, 
	110, 32, 44, 100, 9, 13, 97, 121, 
	32, 44, 9, 13, 104, 117, 117, 32, 
	44, 114, 9, 13, 115, 100, 97, 121, 
	32, 44, 9, 13, 101, 32, 44, 115, 
	9, 13, 100, 97, 121, 32, 44, 9, 
	13, 101, 100, 32, 44, 110, 9, 13, 
	101, 115, 100, 97, 121, 32, 44, 9, 
	13, 0
};

static const char _http_date_single_lengths[] = {
	0, 5, 1, 1, 3, 9, 2, 1, 
	1, 1, 1, 1, 0, 1, 0, 0, 
	1, 0, 0, 1, 1, 0, 0, 0, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 2, 1, 1, 2, 1, 1, 1, 
	2, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 9, 
	2, 1, 1, 1, 0, 0, 0, 1, 
	1, 0, 1, 0, 0, 1, 0, 0, 
	1, 2, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 2, 1, 1, 2, 
	1, 1, 1, 2, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 8, 
	2, 1, 1, 0, 0, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 2, 1, 1, 1, 2, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 2, 1, 1, 2, 1, 1, 3, 
	1, 1, 2, 2, 1, 3, 1, 1, 
	1, 1, 2, 1, 3, 1, 1, 2, 
	2, 1, 3, 1, 1, 1, 1, 2, 
	1, 3, 1, 1, 1, 2, 1, 1, 
	3, 1, 1, 1, 1, 1, 2, 0, 
	0
};

static const char _http_date_range_lengths[] = {
	0, 0, 0, 0, 1, 1, 0, 0, 
	1, 2, 2, 2, 1, 0, 1, 1, 
	0, 1, 1, 1, 2, 1, 1, 1, 
	1, 0, 1, 0, 0, 1, 0, 0, 
	1, 0, 0, 1, 0, 1, 1, 0, 
	0, 1, 1, 0, 0, 1, 0, 0, 
	1, 0, 0, 1, 1, 2, 2, 1, 
	0, 0, 1, 2, 1, 1, 1, 1, 
	2, 1, 0, 1, 1, 0, 1, 1, 
	1, 1, 0, 0, 0, 1, 0, 0, 
	1, 0, 0, 1, 0, 0, 1, 0, 
	1, 1, 0, 0, 1, 1, 0, 0, 
	1, 0, 0, 1, 0, 0, 1, 0, 
	0, 0, 0, 1, 1, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 0, 0, 1, 0, 0, 1, 
	0, 0, 1, 0, 0, 1, 0, 0, 
	0, 0, 1, 0, 1, 0, 0, 1, 
	0, 0, 1, 0, 0, 0, 0, 1, 
	0, 1, 0, 0, 0, 1, 0, 0, 
	1, 0, 0, 0, 0, 0, 1, 0, 
	0
};

static const short _http_date_index_offsets[] = {
	0, 0, 6, 8, 10, 15, 26, 29, 
	31, 34, 38, 42, 46, 48, 50, 52, 
	54, 56, 58, 60, 63, 67, 69, 71, 
	73, 76, 78, 81, 83, 85, 88, 90, 
	92, 95, 98, 100, 103, 106, 109, 112, 
	114, 117, 120, 123, 125, 127, 130, 132, 
	134, 137, 139, 141, 144, 147, 151, 156, 
	167, 170, 172, 175, 179, 181, 183, 185, 
	188, 192, 194, 196, 198, 200, 202, 204, 
	206, 209, 213, 215, 217, 219, 222, 224, 
	226, 229, 231, 233, 236, 239, 241, 244, 
	247, 250, 253, 255, 258, 261, 264, 266, 
	268, 271, 273, 275, 278, 280, 282, 285, 
	294, 297, 299, 301, 303, 305, 308, 310, 
	312, 314, 316, 318, 320, 322, 324, 327, 
	329, 331, 334, 336, 338, 340, 343, 345, 
	347, 349, 351, 353, 355, 357, 359, 361, 
	363, 365, 369, 371, 373, 377, 379, 381, 
	386, 388, 390, 394, 397, 399, 404, 406, 
	408, 410, 412, 416, 418, 423, 425, 427, 
	431, 434, 436, 441, 443, 445, 447, 449, 
	453, 455, 460, 462, 464, 466, 470, 472, 
	474, 479, 481, 483, 485, 487, 489, 493, 
	494
};

static const unsigned char _http_date_indicies[] = {
	0, 2, 3, 4, 5, 1, 6, 1, 
	7, 1, 8, 9, 10, 8, 1, 11, 
	12, 13, 14, 15, 16, 17, 18, 19, 
	11, 1, 20, 21, 1, 22, 1, 23, 
	23, 1, 24, 24, 25, 1, 26, 26, 
	27, 1, 28, 28, 29, 1, 30, 1, 
	31, 1, 32, 1, 33, 1, 34, 1, 
	35, 1, 36, 1, 37, 37, 1, 38, 
	38, 39, 1, 40, 1, 41, 1, 42, 
	1, 26, 26, 1, 43, 1, 44, 44, 
	1, 45, 1, 46, 1, 47, 47, 1, 
	48, 1, 49, 1, 50, 50, 1, 51, 
	52, 1, 53, 1, 54, 54, 1, 55, 
	56, 1, 57, 57, 1, 58, 58, 1, 
	59, 1, 60, 61, 1, 62, 62, 1, 
	63, 63, 1, 64, 1, 65, 1, 66, 
	66, 1, 67, 1, 68, 1, 69, 69, 
	1, 70, 1, 71, 1, 72, 72, 1, 
	73, 73, 1, 73, 73, 74, 1, 75, 
	76, 75, 77, 1, 78, 79, 80, 81, 
	82, 83, 84, 85, 86, 78, 1, 87, 
	88, 1, 89, 1, 90, 90, 1, 91, 
	91, 92, 1, 93, 1, 94, 1, 95, 
	1, 96, 96, 1, 97, 97, 98, 1, 
	99, 1, 100, 1, 101, 1, 102, 1, 
	103, 1, 104, 1, 105, 1, 106, 106, 
	1, 107, 108, 107, 1, 109, 1, 110, 
	1, 111, 1, 112, 112, 1, 113, 1, 
	114, 1, 115, 115, 1, 116, 1, 117, 
	1, 118, 118, 1, 119, 120, 1, 121, 
	1, 122, 122, 1, 123, 124, 1, 125, 
	125, 1, 126, 126, 1, 127, 1, 128, 
	129, 1, 130, 130, 1, 131, 131, 1, 
	132, 1, 133, 1, 134, 134, 1, 135, 
	1, 136, 1, 137, 137, 1, 138, 1, 
	139, 1, 140, 140, 1, 141, 142, 143, 
	144, 145, 146, 147, 148, 1, 149, 150, 
	1, 151, 1, 152, 1, 153, 1, 154, 
	1, 155, 155, 1, 156, 1, 157, 1, 
	158, 1, 159, 1, 160, 1, 161, 1, 
	162, 1, 163, 1, 164, 165, 1, 166, 
	1, 167, 1, 168, 169, 1, 170, 1, 
	171, 1, 172, 1, 173, 174, 1, 175, 
	1, 176, 1, 177, 1, 178, 1, 179, 
	1, 180, 1, 181, 1, 182, 1, 183, 
	1, 184, 1, 185, 1, 75, 76, 75, 
	1, 186, 1, 187, 1, 8, 9, 8, 
	1, 188, 1, 189, 1, 190, 191, 192, 
	190, 1, 193, 1, 194, 1, 190, 191, 
	190, 1, 195, 196, 1, 197, 1, 198, 
	199, 200, 198, 1, 201, 1, 202, 1, 
	203, 1, 204, 1, 198, 199, 198, 1, 
	205, 1, 206, 207, 208, 206, 1, 209, 
	1, 210, 1, 206, 207, 206, 1, 211, 
	212, 1, 213, 1, 214, 215, 216, 214, 
	1, 217, 1, 218, 1, 219, 1, 220, 
	1, 214, 215, 214, 1, 221, 1, 222, 
	223, 224, 222, 1, 225, 1, 226, 1, 
	227, 1, 222, 223, 222, 1, 228, 1, 
	229, 1, 230, 231, 232, 230, 1, 233, 
	1, 234, 1, 235, 1, 236, 1, 237, 
	1, 230, 231, 230, 1, 1, 1, 0
};

static const unsigned char _http_date_trans_targs[] = {
	2, 0, 141, 147, 160, 174, 3, 4, 
	5, 52, 138, 5, 6, 27, 30, 33, 
	39, 43, 46, 49, 7, 25, 8, 9, 
	9, 10, 11, 24, 11, 12, 13, 14, 
	15, 16, 17, 18, 19, 20, 20, 21, 
	22, 23, 183, 26, 9, 28, 29, 9, 
	31, 32, 9, 34, 36, 35, 9, 37, 
	38, 9, 9, 40, 41, 42, 9, 9, 
	44, 45, 9, 47, 48, 9, 50, 51, 
	9, 53, 54, 55, 103, 137, 55, 56, 
	78, 81, 84, 90, 94, 97, 100, 57, 
	76, 58, 59, 59, 60, 61, 62, 63, 
	64, 64, 65, 66, 67, 68, 69, 70, 
	71, 72, 73, 73, 74, 75, 184, 77, 
	59, 79, 80, 59, 82, 83, 59, 85, 
	87, 86, 59, 88, 89, 59, 59, 91, 
	92, 93, 59, 59, 95, 96, 59, 98, 
	99, 59, 101, 102, 59, 104, 112, 115, 
	118, 124, 128, 131, 134, 105, 110, 106, 
	107, 108, 109, 64, 111, 107, 113, 114, 
	107, 116, 117, 107, 119, 121, 120, 107, 
	122, 123, 107, 107, 125, 126, 127, 107, 
	107, 129, 130, 107, 132, 133, 107, 135, 
	136, 107, 139, 140, 142, 143, 5, 52, 
	144, 145, 146, 148, 155, 149, 5, 52, 
	150, 151, 152, 153, 154, 156, 5, 52, 
	157, 158, 159, 161, 168, 162, 5, 52, 
	163, 164, 165, 166, 167, 169, 5, 52, 
	170, 171, 172, 173, 175, 176, 5, 52, 
	177, 178, 179, 180, 181, 182
};

static const char _http_date_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	15, 15, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 25, 
	0, 1, 43, 0, 0, 1, 0, 45, 
	1, 0, 47, 1, 0, 49, 0, 1, 
	0, 0, 0, 0, 33, 0, 0, 41, 
	0, 0, 21, 0, 0, 0, 19, 0, 
	0, 31, 29, 0, 0, 0, 23, 27, 
	0, 0, 39, 0, 0, 37, 0, 0, 
	35, 0, 1, 43, 43, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 25, 0, 1, 0, 0, 0, 
	51, 0, 1, 0, 45, 1, 0, 47, 
	1, 0, 49, 0, 0, 0, 0, 0, 
	33, 0, 0, 41, 0, 0, 21, 0, 
	0, 0, 19, 0, 0, 31, 29, 0, 
	0, 0, 23, 27, 0, 0, 39, 0, 
	0, 37, 0, 0, 35, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	25, 1, 0, 53, 0, 33, 0, 0, 
	41, 0, 0, 21, 0, 0, 0, 19, 
	0, 0, 31, 29, 0, 0, 0, 23, 
	27, 0, 0, 39, 0, 0, 37, 0, 
	0, 35, 0, 0, 0, 0, 7, 7, 
	0, 0, 0, 0, 0, 0, 17, 17, 
	0, 0, 0, 0, 0, 0, 5, 5, 
	0, 0, 0, 0, 0, 0, 13, 13, 
	0, 0, 0, 0, 0, 0, 9, 9, 
	0, 0, 0, 0, 0, 0, 11, 11, 
	0, 0, 0, 0, 0, 0
};

static const char _http_date_eof_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 55, 
	3
};

static const int http_date_start = 1;
static const int http_date_first_final = 183;
static const int http_date_error = 0;

static const int http_date_en_main = 1;


#line 67 "src/http_date.rl"

const char* http_date::day_names[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const char* http_date::month_names[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
const char* http_date::date_format = "%s, %02d %s %04d %02d:%02d:%02d GMT";

http_date::http_date() : tod(0) {}
http_date::http_date(time_t tod) : tod(tod) {}
http_date::http_date(const char* str) : tod(0) { parse(str); }
http_date::http_date(const http_date &o) : tod(o.tod) {}

bool http_date::parse(const char *str)
{
    int cs = http_date_en_main;
    
    const char *mark = NULL;
    const char *p = str;
    const char *pe = str + strlen(str);
    const char *eof = pe;
    struct tm tm;
    
    memset(&tm, 0, sizeof(tm));
    
    
#line 385 "src/http_date.cc"
	{
	cs = http_date_start;
	}

#line 90 "src/http_date.rl"
    
#line 392 "src/http_date.cc"
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
	_keys = _http_date_trans_keys + _http_date_key_offsets[cs];
	_trans = _http_date_index_offsets[cs];

	_klen = _http_date_single_lengths[cs];
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

	_klen = _http_date_range_lengths[cs];
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
	_trans = _http_date_indicies[_trans];
	cs = _http_date_trans_targs[_trans];

	if ( _http_date_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _http_date_actions + _http_date_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 19 "src/http_date.rl"
	{ mark = p; }
	break;
	case 2:
#line 25 "src/http_date.rl"
	{ tm.tm_wday = 0; }
	break;
	case 3:
#line 26 "src/http_date.rl"
	{ tm.tm_wday = 1; }
	break;
	case 4:
#line 27 "src/http_date.rl"
	{ tm.tm_wday = 2; }
	break;
	case 5:
#line 28 "src/http_date.rl"
	{ tm.tm_wday = 3; }
	break;
	case 6:
#line 29 "src/http_date.rl"
	{ tm.tm_wday = 4; }
	break;
	case 7:
#line 30 "src/http_date.rl"
	{ tm.tm_wday = 5; }
	break;
	case 8:
#line 31 "src/http_date.rl"
	{ tm.tm_wday = 6; }
	break;
	case 9:
#line 33 "src/http_date.rl"
	{ tm.tm_mon = 0; }
	break;
	case 10:
#line 34 "src/http_date.rl"
	{ tm.tm_mon = 1; }
	break;
	case 11:
#line 35 "src/http_date.rl"
	{ tm.tm_mon = 2; }
	break;
	case 12:
#line 36 "src/http_date.rl"
	{ tm.tm_mon = 3; }
	break;
	case 13:
#line 37 "src/http_date.rl"
	{ tm.tm_mon = 4; }
	break;
	case 14:
#line 38 "src/http_date.rl"
	{ tm.tm_mon = 5; }
	break;
	case 15:
#line 39 "src/http_date.rl"
	{ tm.tm_mon = 6; }
	break;
	case 16:
#line 40 "src/http_date.rl"
	{ tm.tm_mon = 7; }
	break;
	case 17:
#line 41 "src/http_date.rl"
	{ tm.tm_mon = 8; }
	break;
	case 18:
#line 42 "src/http_date.rl"
	{ tm.tm_mon = 9; }
	break;
	case 19:
#line 43 "src/http_date.rl"
	{ tm.tm_mon = 10; }
	break;
	case 20:
#line 44 "src/http_date.rl"
	{ tm.tm_mon = 11; }
	break;
	case 21:
#line 49 "src/http_date.rl"
	{ tm.tm_mday = atoi(std::string(mark, p - mark).c_str()); }
	break;
	case 22:
#line 50 "src/http_date.rl"
	{ tm.tm_hour = atoi(std::string(mark, p - mark).c_str()); }
	break;
	case 23:
#line 51 "src/http_date.rl"
	{ tm.tm_min = atoi(std::string(mark, p - mark).c_str()); }
	break;
	case 24:
#line 52 "src/http_date.rl"
	{ tm.tm_sec = atoi(std::string(mark, p - mark).c_str()); }
	break;
	case 25:
#line 53 "src/http_date.rl"
	{ tm.tm_year = atoi(std::string(mark, p - mark).c_str()) - 1900; }
	break;
	case 26:
#line 54 "src/http_date.rl"
	{ tm.tm_year = atoi(std::string(mark, p - mark).c_str()); if (tm.tm_year < 38) tm.tm_year += 100; }
	break;
#line 570 "src/http_date.cc"
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
	const char *__acts = _http_date_actions + _http_date_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 1:
#line 20 "src/http_date.rl"
	{ {p++; goto _out; } }
	break;
	case 25:
#line 53 "src/http_date.rl"
	{ tm.tm_year = atoi(std::string(mark, p - mark).c_str()) - 1900; }
	break;
#line 594 "src/http_date.cc"
		}
	}
	}

	_out: {}
	}

#line 91 "src/http_date.rl"
    
    tod = timegm(&tm);
    
    return (cs != http_date_error && cs == http_date_first_final);
}

http_header_string http_date::to_header_string(char *buf, size_t buf_len)
{
    struct tm tm;
    
    /*
    gmtime_r(&tod, &tm);
    size_t len = snprintf(buf, buf_len, date_format,
        day_names[tm.tm_wday], tm.tm_mday, month_names[tm.tm_mon], (tm.tm_year + 1900), tm.tm_hour, tm.tm_min, tm.tm_sec);
    */
    
    if (buf_len < 30) {
        return http_header_string("", 0);
    }
    
    char *p = buf;
    gmtime_r(&tod, &tm);
    int wday = tm.tm_wday & 7;
    int mon = tm.tm_mon % 12;
    int year = tm.tm_year + 1900;
    *(p++) = day_names[wday][0];
    *(p++) = day_names[wday][1];
    *(p++) = day_names[wday][2];
    *(p++) = ',';
    *(p++) = ' ';
    *(p++) = '0' + (tm.tm_mday / 10);
    *(p++) = '0' + (tm.tm_mday % 10);
    *(p++) = ' ';
    *(p++) = month_names[mon][0];
    *(p++) = month_names[mon][1];
    *(p++) = month_names[mon][2];
    *(p++) = ' ';
    *(p++) = '0' + (year / 1000);
    *(p++) = '0' + (year / 100) % 10;
    *(p++) = '0' + (year / 10) % 10;
    *(p++) = '0' + year % 10;
    *(p++) = ' ';
    *(p++) = '0' + (tm.tm_hour / 10);
    *(p++) = '0' + (tm.tm_hour % 10);
    *(p++) = ':';
    *(p++) = '0' + (tm.tm_min / 10);
    *(p++) = '0' + (tm.tm_min % 10);
    *(p++) = ':';
    *(p++) = '0' + (tm.tm_sec / 10);
    *(p++) = '0' + (tm.tm_sec % 10);
    *(p++) = ' ';
    *(p++) = 'G';
    *(p++) = 'M';
    *(p++) = 'T';
    *(p++) = '\0';

    return http_header_string(buf, 29);
}

http_header_string http_date::to_log_string(char *buf, size_t buf_len)
{
    struct tm tm;
    
    if (buf_len < 30) {
        return http_header_string("", 0);
    }
    
    char *p = buf;
    gmtime_r(&tod, &tm);
    int mon = tm.tm_mon % 12;
    int year = tm.tm_year + 1900;
    *(p++) = '[';
    *(p++) = '0' + (tm.tm_mday / 10);
    *(p++) = '0' + (tm.tm_mday % 10);
    *(p++) = '/';
    *(p++) = month_names[mon][0];
    *(p++) = month_names[mon][1];
    *(p++) = month_names[mon][2];
    *(p++) = '/';
    *(p++) = '0' + (year / 1000);
    *(p++) = '0' + (year / 100) % 10;
    *(p++) = '0' + (year / 10) % 10;
    *(p++) = '0' + year % 10;
    *(p++) = ':';
    *(p++) = '0' + (tm.tm_hour / 10);
    *(p++) = '0' + (tm.tm_hour % 10);
    *(p++) = ':';
    *(p++) = '0' + (tm.tm_min / 10);
    *(p++) = '0' + (tm.tm_min % 10);
    *(p++) = ':';
    *(p++) = '0' + (tm.tm_sec / 10);
    *(p++) = '0' + (tm.tm_sec % 10);
    *(p++) = ' ';
    *(p++) = '+';
    *(p++) = '0';
    *(p++) = '0';
    *(p++) = '0';
    *(p++) = '0';
    *(p++) = ']';
    *(p++) = '\0';
    
    return http_header_string(buf, 29);
}

http_header_string http_date::to_iso_string(char *buf, size_t buf_len)
{
    struct tm tm;
    
    if (buf_len < 30) {
        return http_header_string("", 0);
    }
    
    char *p = buf;
    gmtime_r(&tod, &tm);
    int mon = tm.tm_mon % 12;
    int year = tm.tm_year + 1900;
    *(p++) = '0' + (year / 1000);
    *(p++) = '0' + (year / 100) % 10;
    *(p++) = '0' + (year / 10) % 10;
    *(p++) = '0' + year % 10;
    *(p++) = '0' + ((mon + 1) / 10);
    *(p++) = '0' + ((mon + 1) % 10);
    *(p++) = '0' + (tm.tm_mday / 10);
    *(p++) = '0' + (tm.tm_mday % 10);
    *(p++) = '0' + (tm.tm_hour / 10);
    *(p++) = '0' + (tm.tm_hour % 10);
    *(p++) = '0' + (tm.tm_min / 10);
    *(p++) = '0' + (tm.tm_min % 10);
    *(p++) = '0' + (tm.tm_sec / 10);
    *(p++) = '0' + (tm.tm_sec % 10);
    *(p++) = '\0';
    
    return http_header_string(buf, 29);
}

std::string http_date::to_string(http_date_format fmt)
{
    char buf[32];
    switch (fmt) {
        case http_date_format_header:   to_header_string(buf, 32);  break;
        case http_date_format_log:      to_log_string(buf, 32);     break;
        case http_date_format_iso:      to_iso_string(buf, 32);     break;
    }
    return buf;
}
