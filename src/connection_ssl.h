//
//  connection_ssl.h
//

#ifndef connection_ssl_h
#define connection_ssl_h

typedef struct bio_st BIO;

struct connection_ssl
{
    static int bio_write(BIO *b, const char *buf, int len);
    static int bio_read(BIO *b, char *buf, int len);
    static long bio_ctrl(BIO *b, int cmd, long num, void *ptr);
    static int bio_create(BIO *b);
    static int bio_destroy(BIO *b);
};

#endif
