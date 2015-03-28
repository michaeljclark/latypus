//
//  http_common.cc
//

#include <cstring>
#include <map>
#include <vector>
#include <string>

#include "http_common.h"

int http_common::sanitize_path(char *s)
{
    char *r, *w;
    int last_was_slash = 0;
    
    r = w = s;
    while(*r != 0)
    {
        /* Ignore duplicate /'s */
        if (*r == '/' && last_was_slash) {
		    r++;
		    continue;
		}
	    /* Calculate /../ in a secure way and avoid */
	    if (last_was_slash && *r == '.') {
		    if (*(r+1) == '.') {
                /* skip past .. or ../ with read pointer */
                if (*(r+2) == '/') r += 3;
                else if (*(r+2) == 0) r += 2;
                /* skip back to last / with write pointer */
                if (w > s+1) {
                    w--;
                    while(*(w-1) != '/') { w--; }
                    continue;
                } else {
                    return -1; /* Bad Request */
                }
		    } else if (*(r+1) == '/') {
                r += 2;
                continue;
		    }
		}
	    *w = *r;
	    last_was_slash = (*r == '/');
	    r++;
	    w++;
	}
    *w = 0;
    return 0;
}
