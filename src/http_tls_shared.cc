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
#include "hex.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "http_tls_shared.h"


/* http_tls_shared */

bool http_tls_shared::tls_session_debug = false;
const int http_tls_shared::max_session_count = 32768;
std::mutex http_tls_shared::session_mutex;
http_tls_session_map http_tls_shared::session_map;
http_tls_session_dequeue http_tls_shared::session_deque;
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

void http_tls_shared::tls_expire_sessions(SSL_CTX *ctx)
{
    config *cfg = static_cast<config*>(SSL_CTX_get_ex_data(ctx, 0));
    time_t current_time = time(nullptr);
    for (auto si = session_deque.begin(); si != session_deque.end(); ) {
        auto &tls_sess = *si;
        // expire sessions that are older than the timeout value
        // or if the number of sessions is larger than max_session_count
        if (tls_sess->sess_time < current_time - cfg->tls_session_timeout ||
            session_deque.size() > cfg->tls_session_count)
        {
            if (tls_session_debug) {
                log_debug("%s: expiring session: id=%s", __func__, tls_sess->sess_key.c_str());
            }
            session_map.erase(tls_sess->sess_key);
            si = session_deque.erase(si);
        } else {
            break;
        }
    }
}

int http_tls_shared::tls_new_session_cb(struct ssl_st *ssl, SSL_SESSION *sess)
{
    unsigned int sess_id_len;
    const unsigned char *sess_id = SSL_SESSION_get_id(sess, &sess_id_len);
    std::string sess_key = hex::encode(sess_id, sess_id_len);
    session_mutex.lock();
    size_t sess_der_len = i2d_SSL_SESSION(sess, NULL);
    unsigned char *sess_der = new unsigned char[sess_der_len];
    time_t current_time = time(nullptr);
    if (sess_der) {
        unsigned char *p = sess_der;
        i2d_SSL_SESSION(sess, &p);
        auto si = session_map.insert(http_tls_session_entry
            (sess_key, std::make_shared<http_tls_session>(sess_key, current_time, sess_der, sess_der_len)));
        auto &tls_sess = *si.first->second;
        session_deque.push_back(si.first->second);
        session_mutex.unlock();
        if (tls_session_debug) {
            log_debug("%s: added session: id=%s len=%lu", __func__, sess_key.c_str(), tls_sess.sess_der_len);
        }
        return 0;
    } else {
        if (tls_session_debug) {
            log_debug("%s: failed to add session: id=%s", __func__, sess_key.c_str());
        }
        session_mutex.unlock();
        return -1;
    }
}

void http_tls_shared::tls_remove_session_cb(struct ssl_ctx_st *ctx, SSL_SESSION *sess)
{
    unsigned int sess_id_len;
    const unsigned char *sess_id = SSL_SESSION_get_id(sess, &sess_id_len);
    std::string sess_key = hex::encode(sess_id, sess_id_len);
    session_mutex.lock();
    session_map.erase(sess_key);
    session_mutex.unlock();
    if (tls_session_debug) {
        log_debug("%s: removed session: id=%s", __func__, sess_key.c_str());
    }
}

SSL_SESSION * http_tls_shared::tls_get_session_cb(struct ssl_st *ssl, unsigned char *sess_id, int sess_id_len, int *copy)
{
    *copy = 0;
    std::string sess_key = hex::encode(sess_id, sess_id_len);
    session_mutex.lock();
    tls_expire_sessions(ssl->ctx);
    auto si = session_map.find(sess_key);
    if (si != session_map.end()) {
        auto &tls_sess = *si->second;
        session_mutex.unlock();
        if (tls_session_debug) {
            log_debug("%s: lookup session: cache hit: id=%s len=%lu", __func__, sess_key.c_str(), tls_sess.sess_der_len);
        }
        unsigned const char *p = tls_sess.sess_der;
        return d2i_SSL_SESSION(NULL, &p, tls_sess.sess_der_len);
    }
    session_mutex.unlock();
    if (tls_session_debug) {
        log_debug("%s: lookup session: cache miss: id=%s", __func__, sess_key.c_str());
    }
    return nullptr;
}

SSL_CTX* http_tls_shared::init_client(protocol *proto, config_ptr cfg)
{
    SSL_library_init();
    SSL_load_error_strings();
    
    CRYPTO_set_locking_callback(http_tls_shared::tls_locking_function);
    CRYPTO_THREADID_set_callback(http_tls_shared::tls_threadid_function);
    
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_ex_data(ctx, 0, cfg.get());
    
#ifdef SSL_OP_NO_SSLv2
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#endif
#ifdef SSL_OP_NO_SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif
    
    if (cfg->tls_cipher_list.length() > 0) {
        SSL_CTX_set_cipher_list(ctx, cfg->tls_cipher_list.c_str());
    }
    
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
    SSL_CTX_set_ex_data(ctx, 0, cfg.get());

#ifdef SSL_OP_NO_SSLv2
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
#endif
#ifdef SSL_OP_NO_SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

    if (cfg->tls_cipher_list.length() > 0) {
        SSL_CTX_set_cipher_list(ctx, cfg->tls_cipher_list.c_str());
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL |
                                        SSL_SESS_CACHE_NO_AUTO_CLEAR |
                                        SSL_SESS_CACHE_SERVER);
    SSL_CTX_sess_set_new_cb(ctx, http_tls_shared::tls_new_session_cb);
    SSL_CTX_sess_set_remove_cb(ctx, http_tls_shared::tls_remove_session_cb);
    SSL_CTX_sess_set_get_cb(ctx, http_tls_shared::tls_get_session_cb);

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
