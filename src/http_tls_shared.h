//
//  http_tls_shared.h
//

#ifndef http_tls_shared_h
#define http_tls_shared_h

struct http_tls_shared
{
    static std::once_flag lock_init_flag;
    static std::vector<std::shared_ptr<std::mutex>> locks;

    static void tls_threadid_function(CRYPTO_THREADID *thread_id);
    static void tls_locking_function(int mode, int n, const char *file, int line);
    static int tls_log_errors(const char *str, size_t len, void *bio);
    
    static SSL_CTX* init_client(protocol *proto, config_ptr cfg);
    static SSL_CTX* init_server(protocol *proto, config_ptr cfg);
    
    static std::string log_cipher(SSL *ssl);
};

#endif
