//
//  http_tls_shared.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <map>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "http_tls_shared.h"


std::once_flag http_tls_shared::lock_init_flag;
std::vector<std::shared_ptr<std::mutex>> http_tls_shared::locks;

void http_tls_shared::tls_threadid_function(CRYPTO_THREADID *thread_id)
{
    CRYPTO_THREADID_set_pointer(thread_id, (void*)pthread_self());
}

void http_tls_shared::tls_locking_function(int mode, int n, const char *file, int line)
{
    std::call_once(lock_init_flag, [](){
        size_t num_locks = CRYPTO_num_locks();
        locks.resize(CRYPTO_num_locks());
        for (size_t i = 0; i < num_locks; i++) {
            locks[i] = std::make_shared<std::mutex>();
        }
    });
    
    if (mode & CRYPTO_LOCK) {
        locks[n]->lock();
    } else if (mode & CRYPTO_UNLOCK) {
        locks[n]->unlock();
    }
}

int http_tls_shared::tls_log_errors(const char *str, size_t len, void *bio)
{
    fprintf(stderr, "%s", str);
    return 0;
}

SSL_CTX* http_tls_shared::init_client(protocol *proto, config_ptr cfg)
{
    SSL_library_init();
    SSL_load_error_strings();
    
    CRYPTO_set_locking_callback(http_tls_shared::tls_locking_function);
    CRYPTO_THREADID_set_callback(http_tls_shared::tls_threadid_function);
    
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
#ifdef SSL_OP_NO_SSLv2
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#endif
#ifdef SSL_OP_NO_SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
    
    if ((!SSL_CTX_load_verify_locations(ctx, cfg->tls_ca_file.c_str(), NULL)) ||
        (!SSL_CTX_set_default_verify_paths(ctx))) {
        ERR_print_errors_cb(http_tls_shared::tls_log_errors, NULL);
        log_fatal_exit("%s failed to load cacert: %s",
                       proto->name.c_str(), cfg->tls_ca_file.c_str());
    } else {
        log_debug("%s loaded cacert: %s",
                  proto->name.c_str(), cfg->tls_ca_file.c_str());
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 9);
    
    return ctx;
}

SSL_CTX* http_tls_shared::init_server(protocol *proto, config_ptr cfg)
{
    SSL_library_init();
    SSL_load_error_strings();
    
    CRYPTO_set_locking_callback(http_tls_shared::tls_locking_function);
    CRYPTO_THREADID_set_callback(http_tls_shared::tls_threadid_function);
    
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
#ifdef SSL_OP_NO_SSLv2
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#endif
#ifdef SSL_OP_NO_SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
    
    if (SSL_CTX_use_certificate_file(ctx,
                                     cfg->tls_cert_file.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_cb(http_tls_shared::tls_log_errors, NULL);
        log_fatal_exit("%s failed to load certificate: %s",
                       proto->name.c_str(), cfg->tls_cert_file.c_str());
    } else {
        log_info("%s loaded cert: %s",
                 proto->name.c_str(), cfg->tls_cert_file.c_str());
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx,
                                    cfg->tls_key_file.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_cb(http_tls_shared::tls_log_errors, NULL);
        log_fatal_exit("%s failed to load private key: %s",
                       proto->name.c_str(), cfg->tls_key_file.c_str());
    } else {
        log_info("%s loaded key: %s",
                 proto->name.c_str(), cfg->tls_key_file.c_str());
    }
    
    return ctx;
}
