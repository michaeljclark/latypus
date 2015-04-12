//
//  http_tls_shared.h
//

#ifndef http_tls_shared_h
#define http_tls_shared_h

struct http_tls_session;
typedef std::shared_ptr<http_tls_session> http_tls_session_ptr;
typedef std::map<std::string,http_tls_session_ptr> http_tls_session_map;
typedef std::pair<std::string,http_tls_session_ptr> http_tls_session_entry;

struct http_tls_session
{
    unsigned char *sess_der;
    size_t sess_der_len;
    
    http_tls_session() : sess_der(nullptr), sess_der_len(0) {}
    http_tls_session(const http_tls_session &o) : sess_der(nullptr), sess_der_len(o.sess_der_len)
    {
        if (o.sess_der && o.sess_der_len) {
            sess_der = new unsigned char[sess_der_len];
            memcpy(sess_der, o.sess_der, sess_der_len);
        }
    }
    
    ~http_tls_session()
    {
        if (sess_der) delete [] sess_der;
    }
};

struct http_tls_shared
{
    static bool tls_session_debug;
    static std::mutex session_mutex;
    static http_tls_session_map session_map;
    static std::once_flag lock_init_flag;
    static std::vector<std::shared_ptr<std::mutex>> locks;

    static void tls_threadid_function(CRYPTO_THREADID *thread_id);
    static void tls_locking_function(int mode, int n, const char *file, int line);
    static int tls_log_errors(const char *str, size_t len, void *bio);
    
    static int tls_new_session_cb(struct ssl_st *ssl, SSL_SESSION *sess);
    static void tls_remove_session_cb(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    static SSL_SESSION * tls_get_session_cb(struct ssl_st *ssl, unsigned char *data, int len, int *copy);

    static SSL_CTX* init_client(protocol *proto, config_ptr cfg);
    static SSL_CTX* init_server(protocol *proto, config_ptr cfg);
    
    static std::string log_cipher(SSL *ssl);
};

#endif
