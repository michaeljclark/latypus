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

%%{
    
    machine http_date;
    
    action mark             { mark = fpc; }
    action done             { fbreak; }
    
    SP = space+;
    GMT = /GMT/;
    
    Sunday = ( /Sun/ | /Sunday/ ) %{ tm.tm_wday = 0; };
    Monday = ( /Mon/ | /Monday/ ) %{ tm.tm_wday = 1; };
    Tuesday = ( /Tue/ | /Tuesday/ ) %{ tm.tm_wday = 2; };
    Wednesday = ( /Wed/ | /Wednesday/ ) %{ tm.tm_wday = 3; };
    Thursday = ( /Thu/ | /Thursday/ ) %{ tm.tm_wday = 4; };
    Friday = ( /Fri/ | /Friday/ ) %{ tm.tm_wday = 5; };
    Saturday = ( /Sat/ | /Saturday/ ) %{ tm.tm_wday = 6; };
    
    Jan = /Jan/ %{ tm.tm_mon = 0; };
    Feb = /Feb/ %{ tm.tm_mon = 1; };
    Mar = /Mar/ %{ tm.tm_mon = 2; };
    Apr = /Apr/ %{ tm.tm_mon = 3; };
    May = /May/ %{ tm.tm_mon = 4; };
    Jun = /Jun/ %{ tm.tm_mon = 5; };
    Jul = /Jul/ %{ tm.tm_mon = 6; };
    Aug = /Aug/ %{ tm.tm_mon = 7; };
    Sep = /Sep/ %{ tm.tm_mon = 8; };
    Oct = /Oct/ %{ tm.tm_mon = 9; };
    Nov = /Nov/ %{ tm.tm_mon = 10; };
    Dec = /Dec/ %{ tm.tm_mon = 11; };
    
    day_name = ( Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Sunday );
    month_name = ( Jan | Feb | Mar | Apr | May | Jun | Jul | Aug | Sep | Oct | Nov | Dec );
    
    day = digit{1,2} >mark %{ tm.tm_mday = atoi(std::string(mark, fpc - mark).c_str()); };
    hour = digit{2} >mark %{ tm.tm_hour = atoi(std::string(mark, fpc - mark).c_str()); };
    minute = digit{2} >mark %{ tm.tm_min = atoi(std::string(mark, fpc - mark).c_str()); };
    second = digit{2} >mark %{ tm.tm_sec = atoi(std::string(mark, fpc - mark).c_str()); };
    year4 = digit{4} >mark %{ tm.tm_year = atoi(std::string(mark, fpc - mark).c_str()) - 1900; };
    year2 = digit{2} >mark %{ tm.tm_year = atoi(std::string(mark, fpc - mark).c_str()); if (tm.tm_year < 38) tm.tm_year += 100; };

    asctime_date = day_name SP month_name SP day SP hour ":" minute ":" second SP year4;
    rfc850_date = day_name "," SP day "-" month_name "-" year2 SP hour ":" minute ":" second SP GMT;
    IMF_fixdate = day_name "," SP day SP month_name SP year4 SP hour ":" minute ":" second SP GMT;
    
    HTTP_Date = ( IMF_fixdate | rfc850_date | asctime_date );
    
    main := HTTP_Date %done;
    
}%%

%% write data;

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
    
    %% write init;
    %% write exec;
    
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
    *(p++) = '-';
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
