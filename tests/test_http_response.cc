#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
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

static const char * response_1_ok = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 800\r\nCache-Control: no-cache, no-store\r\n\r\n";
static const char * response_2_body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody";

class test_http_response : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_http_response);
    CPPUNIT_TEST(test_construct_response_1_ok);
    CPPUNIT_TEST(test_parse_response_1_ok);
    CPPUNIT_TEST(test_parse_response_2_body_fragment);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_construct_response_1_ok()
    {
        // test constructing response
        http_response response;
        response.resize(4096);
        response.set_http_version(kHTTPVersion11);
        response.set_status_code(HTTPStatusCodeOK);
        response.set_reason_phrase(kHTTPStatusTextOK);
        response.set_header_field(kHTTPHeaderContentType, "text/html");
        response.set_header_field(kHTTPHeaderContentLength, "800");
        response.set_header_field(kHTTPHeaderCacheControl, "no-cache");
        response.set_header_field(kHTTPHeaderCacheControl, "no-store");
        CPPUNIT_ASSERT(response.header_map.size() == 3);
        CPPUNIT_ASSERT(response.to_string() == response_1_ok);
    }

    void test_parse_response_1_ok()
    {
        // test parsing response with \r\n
        http_response response;
        response.resize(4096);
        size_t bytes_parsed = response.parse(response_1_ok, strlen(response_1_ok));
        CPPUNIT_ASSERT(bytes_parsed == strlen(response_1_ok));
        CPPUNIT_ASSERT(response.header_map.size() == 3);
        CPPUNIT_ASSERT(response.is_finished() == true);
        CPPUNIT_ASSERT(response.has_error() == false);
    }
    
    void test_parse_response_2_body_fragment()
    {
        // test parsing response with \r\n
        http_response response;
        response.resize(4096);
        size_t bytes_parsed = response.parse(response_2_body, strlen(response_2_body));
        CPPUNIT_ASSERT(bytes_parsed == strlen(response_2_body) - strlen("body"));
        CPPUNIT_ASSERT(response.header_map.size() == 1);
        CPPUNIT_ASSERT(response.is_finished() == true);
        CPPUNIT_ASSERT(response.has_error() == false);
        CPPUNIT_ASSERT(strcmp(response.get_body_start(), "body") == 0);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_http_response::suite());
    runner.run(controller);
    outputer.write();
        
    return 0;
}

