//
//  test_url.cc
//

#include <string>
#include <iostream>
#include <memory>

#include "url.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>


static const char* test_url_1_ok = "http://www.apple.com/";
static const char* test_url_2_ok = "http://localhost:81/foo";
static const char* test_url_3_ok = "https://192.168.0.1/bar";
static const char* test_url_4_ok = "https://192.168.0.1:444/bar";
static const char* test_url_5_err = "https:/192.168.0.1:444/bar";

class test_url : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_url);
    CPPUNIT_TEST(test_parse_url_1_ok);
    CPPUNIT_TEST(test_parse_url_2_ok);
    CPPUNIT_TEST(test_parse_url_3_ok);
    CPPUNIT_TEST(test_parse_url_4_ok);
    CPPUNIT_TEST(test_parse_url_5_err);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_parse_url_1_ok()
    {
        url url(test_url_1_ok);
        CPPUNIT_ASSERT(url.scheme == "http");
        CPPUNIT_ASSERT(url.host == "www.apple.com");
        CPPUNIT_ASSERT(url.port == 80);
        CPPUNIT_ASSERT(url.path == "/");
        CPPUNIT_ASSERT(url.valid == true);
        CPPUNIT_ASSERT(url.to_string() == test_url_1_ok);
    }

    void test_parse_url_2_ok()
    {
        url url(test_url_2_ok);
        CPPUNIT_ASSERT(url.scheme == "http");
        CPPUNIT_ASSERT(url.host == "localhost");
        CPPUNIT_ASSERT(url.port == 81);
        CPPUNIT_ASSERT(url.path == "/foo");
        CPPUNIT_ASSERT(url.valid == true);
        CPPUNIT_ASSERT(url.to_string() == test_url_2_ok);
    }

    void test_parse_url_3_ok()
    {
        url url(test_url_3_ok);
        CPPUNIT_ASSERT(url.scheme == "https");
        CPPUNIT_ASSERT(url.host == "192.168.0.1");
        CPPUNIT_ASSERT(url.port == 443);
        CPPUNIT_ASSERT(url.path == "/bar");
        CPPUNIT_ASSERT(url.valid == true);
        CPPUNIT_ASSERT(url.to_string() == test_url_3_ok);
    }

    void test_parse_url_4_ok()
    {
        url url(test_url_4_ok);
        CPPUNIT_ASSERT(url.scheme == "https");
        CPPUNIT_ASSERT(url.host == "192.168.0.1");
        CPPUNIT_ASSERT(url.port == 444);
        CPPUNIT_ASSERT(url.path == "/bar");
        CPPUNIT_ASSERT(url.valid == true);
        CPPUNIT_ASSERT(url.to_string() == test_url_4_ok);
    }

    void test_parse_url_5_err()
    {
        url url(test_url_5_err);
        CPPUNIT_ASSERT(url.valid == false);
        CPPUNIT_ASSERT(url.to_string() != test_url_5_err);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_url::suite());
    runner.run(controller);
    outputer.write();
    
    return 0;
}
