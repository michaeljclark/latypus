#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <map>

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"
#include "http_request.h"
#include "http_response.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>

static const char * request_1_ok = "GET /textinputassistant/tia.png HTTP/1.1\r\n\r\n";
static const char * request_2_ok = "GET /textinputassistant/tia.png HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
static const char * request_3_ok = "GET /textinputassistant/tia.png HTTP/1.1\nHost: www.google.com\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0\nAccept: image/png,image/*;q=0.8,*/*;q=0.5\nAccept-Language: en-US,en;q=0.5\nAccept-Encoding: gzip, deflate\nReferer: https://www.google.com.sg/\nConnection: keep-alive\nIf-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT\nCache-Control: max-age=0\n\n";
static const char * request_4_ok = "GET /textinputassistant/tia.png HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0\r\nAccept: image/png,image/*;q=0.8,*/*;q=0.5\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: https://www.google.com.sg/\r\nConnection: keep-alive\r\nIf-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT\r\nCache-Control: max-age=0\r\n\r\n";
static const char * request_5_err = "GET /textinputassistant/tia.png HTTPX/1.1\n\n";
static const char * request_6_body = "POST /textinputassistant/tia.png HTTP/1.1\r\n\r\nbody";

class test_http_request : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_http_request);
    CPPUNIT_TEST(test_construct_request_1_ok);
    CPPUNIT_TEST(test_construct_request_2_ok);
    CPPUNIT_TEST(test_parse_request_1_ok);
    CPPUNIT_TEST(test_parse_request_2_ok);
    CPPUNIT_TEST(test_parse_request_3_ok);
    CPPUNIT_TEST(test_parse_request_4_ok);
    CPPUNIT_TEST(test_parse_request_5_err);
    CPPUNIT_TEST(test_parse_request_6_body_fragment);
    CPPUNIT_TEST(test_parse_request_to_string);
    CPPUNIT_TEST(test_parse_request_to_buffer);
    CPPUNIT_TEST(test_parse_request_buffer_overflow);
    CPPUNIT_TEST(test_parse_request_max_headers_overflow);
    CPPUNIT_TEST(test_parse_request_no_buffer);
    CPPUNIT_TEST(test_parse_request_incremental);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_construct_request_1_ok()
    {
        // test constructing request
        http_request request;
        request.resize(4096, 64);
        request.set_request_method(kHTTPMethodGET);
        request.set_request_uri("/textinputassistant/tia.png");
        request.set_http_version(kHTTPVersion11);
        CPPUNIT_ASSERT(request.to_string() == request_1_ok);
    }

    void test_construct_request_2_ok()
    {
        // test constructing request
        http_request request;
        request.resize(4096, 64);
        request.set_request_method(kHTTPMethodGET);
        request.set_request_uri("/textinputassistant/tia.png");
        request.set_http_version(kHTTPVersion11);
        request.set_header_field(kHTTPHeaderHost, "www.google.com");
        CPPUNIT_ASSERT(request.to_string() == request_2_ok);
    }

    void test_parse_request_1_ok()
    {
        // test parsing headers with \n
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_1_ok, strlen(request_1_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_1_ok));
        CPPUNIT_ASSERT(request.header_map.size() == 0);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
    }

    void test_parse_request_2_ok()
    {
        // test parsing headers with \r\n
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_2_ok, strlen(request_2_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_2_ok));
        CPPUNIT_ASSERT(request.header_map.size() == 1);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
    }

    void test_parse_request_3_ok()
    {
        // test parsing headers with \r\n
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_3_ok, strlen(request_3_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_3_ok));
        CPPUNIT_ASSERT(request.header_map.size() == 9);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
    }

    void test_parse_request_4_ok()
    {
        // test parsing headers with \r\n
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(request.header_map.size() == 9);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
    }

    void test_parse_request_5_err()
    {
        // test parsing headers with \n
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_5_err, strlen(request_5_err));
        CPPUNIT_ASSERT(bytes_parsed != strlen(request_5_err));
        CPPUNIT_ASSERT(request.header_map.size() == 0);
        CPPUNIT_ASSERT(request.is_finished() == false);
        CPPUNIT_ASSERT(request.has_error() == true);
    }

    void test_parse_request_6_body_fragment()
    {
        // test parsing headers with body fragment
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_6_body, strlen(request_6_body));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_6_body) - strlen("body"));
        CPPUNIT_ASSERT(request.header_map.size() == 0);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
        CPPUNIT_ASSERT(strcmp(request.get_body_start(), "body") == 0);
    }

    void test_parse_request_to_string()
    {
        // test to_string matches parsed headers (only with \r\n)
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(request.to_string() == request_4_ok);
    }

    void test_parse_request_to_buffer()
    {
        // test to_buffer matches parsed headers (only with \r\n)
        char buf[4096];
        http_request request;
        request.resize(4096, 64);
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        size_t bytes_written = request.to_buffer(buf, sizeof(buf));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_written == strlen(request_4_ok));
        CPPUNIT_ASSERT(memcmp(buf, (const char*)request_4_ok, sizeof(request_4_ok)) == 0);
    }
    
    void test_parse_request_buffer_overflow()
    {
        // test header buffer overflow
        http_request request;
        request.resize(64, 64);
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(request.has_error() == true);
        CPPUNIT_ASSERT(request.has_overflow() == true);
        CPPUNIT_ASSERT(request.to_string() != request_4_ok);
    }

    void test_parse_request_max_headers_overflow()
    {
        // test header buffer overflow
        http_request request;
        request.resize(4096, 2);
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(request.has_error() == true);
        CPPUNIT_ASSERT(request.has_overflow() == true);
        CPPUNIT_ASSERT(request.to_string() != request_4_ok);
    }

    void test_parse_request_no_buffer()
    {
        // test failure to call resize
        http_request request;
        size_t bytes_parsed = request.parse(request_4_ok, strlen(request_4_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(request_4_ok));
        CPPUNIT_ASSERT(request.has_error() == true);
        CPPUNIT_ASSERT(request.has_overflow() == true);
        CPPUNIT_ASSERT(request.to_string() != request_4_ok);
    }

    void test_parse_request_incremental()
    {
        // test parsing headers with \r\n
        http_request request;
        request.resize(4096, 64);
        size_t seg_1 = strlen(request_4_ok) - strlen(request_4_ok) / 2;
        size_t seg_2 = strlen(request_4_ok) - seg_1;
        size_t bytes_parsed = 0;
        bytes_parsed = request.parse(request_4_ok, seg_1);
        CPPUNIT_ASSERT(bytes_parsed == seg_1);
        CPPUNIT_ASSERT(request.is_finished() == false);
        CPPUNIT_ASSERT(request.has_error() == false);
        bytes_parsed = request.parse(request_4_ok + seg_1, seg_2);
        CPPUNIT_ASSERT(bytes_parsed == seg_1 + seg_2);
        CPPUNIT_ASSERT(request.header_map.size() == 9);
        CPPUNIT_ASSERT(request.is_finished() == true);
        CPPUNIT_ASSERT(request.has_error() == false);
        CPPUNIT_ASSERT(request.to_string() == request_4_ok);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);

    controller.addListener(&result);
    runner.addTest(test_http_request::suite());
    runner.run(controller);
    outputer.write();
    
    return 0;
}

