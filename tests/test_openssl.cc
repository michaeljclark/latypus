//
//  test_openssl.cc
//

#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <csignal>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>

BIO *bio_err = NULL;

static void lock_dbg_cb(int mode, int type, const char *file, int line)
{
    static int modes[CRYPTO_NUM_LOCKS]; /* = {0, 0, ... } */
    const char *errstr = NULL;
    int rw;
    
    rw = mode & (CRYPTO_READ|CRYPTO_WRITE);
    if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE)))
    {
        errstr = "invalid mode";
        goto err;
    }
    
    if (type < 0 || type >= CRYPTO_NUM_LOCKS)
    {
        errstr = "type out of bounds";
        goto err;
    }
    
    if (mode & CRYPTO_LOCK)
    {
        if (modes[type])
        {
            errstr = "already locked";
            /* must not happen in a single-threaded program
             * (would deadlock) */
            goto err;
        }
        
        modes[type] = rw;
    }
    else if (mode & CRYPTO_UNLOCK)
    {
        if (!modes[type])
        {
            errstr = "not locked";
            goto err;
        }
        
        if (modes[type] != rw)
        {
            errstr = (rw == CRYPTO_READ) ?
            "CRYPTO_r_unlock on write lock" :
            "CRYPTO_w_unlock on read lock";
        }
        
        modes[type] = 0;
    } else {
        errstr = "invalid mode";
        goto err;
    }
    
err:
    if (errstr) {
        /* we cannot use bio_err here */
        fprintf(stderr, "openssl (lock_dbg_cb): %s (mode=%d, type=%d) at %s:%d\n",
                errstr, mode, type, file, line);
    }
}

/*
 Server Side SNI
static int ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    const char * hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1) {
        printf("hostname=%s\n", hn);
    }
    // In the callback, retrieve the client-supplied servername with SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name).
    // Figure out the right SSL_CTX to go with that host name, then switch the SSL object to that SSL_CTX with SSL_set_SSL_CTX()
 
    return SSL_TLSEXT_ERR_OK;
}

 SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
 SSL_CTX_set_tlsext_servername_arg(ctx, NULL);
*/

#define RSA_CLIENT_CA_CERT "data/ca-bundle.crt"

class test_openssl : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_openssl);
    CPPUNIT_TEST(test_openssl_connect);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_openssl_connect()
    {
        short int       s_port = 443;
        const char      *s_ipaddr = "74.125.200.105";
        const char      *s_name = "www.google.com";

        int ret;
        
        signal(SIGPIPE,SIG_IGN);
        
        SSL_library_init();
        CRYPTO_set_locking_callback(lock_dbg_cb);
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        //printf("%s\n", SSLeay_version(SSLEAY_VERSION));
        
        /* create ssl context */
        const SSL_METHOD *meth = TLSv1_2_client_method();
        SSL_CTX *ctx = SSL_CTX_new(meth);
        
        // https://www.openssl.org/docs/apps/ciphers.html
        // https://community.qualys.com/blogs/securitylabs/2013/08/05/configuring-apache-nginx-and-openssl-for-forward-secrecy
        // https://www.ssllabs.com/ssltest/analyze.html?d=git.earthbuzz.com
        // check filter: openssl ciphers -v 'TLSv1.2:!aNULL:!eNULL'
        // http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
        
        if (!SSL_CTX_load_verify_locations(ctx, RSA_CLIENT_CA_CERT, NULL)) {
            BIO_print_errors_fp(stderr);
            exit(1);
        }
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 9);
        
        /* create socket */
        int sock = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            fprintf(stderr, "sock: %s\n", strerror(errno));
            exit(1);
        }
        struct sockaddr_in server_addr;
        memset (&server_addr, '\0', sizeof(server_addr));
        server_addr.sin_family      = AF_INET;
        server_addr.sin_port        = htons(s_port);
        server_addr.sin_addr.s_addr = inet_addr(s_ipaddr);
        
        /* Establish a TCP/IP connection to the SSL client */
        ret = connect(sock, (struct sockaddr*) &server_addr, sizeof(server_addr));
        if (ret < 0) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
            exit(1);
        }
        
        /* Assign the socket into the SSL structure (SSL and socket without BIO) and perform ssl handshake */
        SSL *ssl = SSL_new (ctx);
        //SSL_set_cipher_list(ssl, "ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!eNULL");
        //SSL_set_cipher_list(ssl, "ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!eNULL");
        //SSL_set_cipher_list(ssl, "EECDH+TLSv1.2+AESGCM:!aNULL:!eNULL");
        SSL_set_cipher_list(ssl, "EECDH+TLSv1.2+AES256:EDH+TLSv1.2+AES256:!aNULL:!eNULL");
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, s_name);
        ret = SSL_connect(ssl);
        if (ret < 0) {
            char verify_err[120];
            printf("verify result: %s\n", ERR_error_string((uint32_t)SSL_get_verify_result(ssl), verify_err));
            BIO_print_errors_fp(stderr);
            exit(1);
        }
        
        /* Informational output (optional) */
        printf("SSL servername: %s\n", SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name));
        printf("SSL cipher:     %s\n", SSL_get_cipher(ssl));
        printf("SSL version:    %s\n", SSL_get_version(ssl));
        
        /* Get the server's certificate (optional) */
        X509 *server_cert = SSL_get_peer_certificate (ssl);
        
        if (server_cert != NULL)
        {
            char  *subject = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
            if (subject) {
                printf ("SSL subject:    %s\n", subject);
                free (subject);
            }
            
            char *issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
            if (issuer) {
                printf ("SSL issuer:     %s\n", issuer);
                free(issuer);
            }
            
            X509_free(server_cert);
        }
        
        /* shutdown SSL socket */
        ret = SSL_shutdown(ssl);
        if (ret < 0) {
            BIO_print_errors_fp(stderr);
            exit(1);
        }
        ret = close(sock);
        if (ret < 0) {
            fprintf(stderr, "close: %s\n", strerror(errno));
            exit(1);
        }
        
        /* Free the SSL structure */
        SSL_free(ssl);
        
        /* Free the SSL_CTX structure */
        SSL_CTX_free(ctx);
        
        EVP_cleanup();
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_openssl::suite());
    runner.run(controller);
    outputer.write();
}
