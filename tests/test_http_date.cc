#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>

#include "http_common.h"
#include "http_date.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>


static const char* testdate_1_in = "Thu, 24 Oct 2013 00:11:57 GMT";
static const char* testdate_1_out = "Thu, 24 Oct 2013 00:11:57 GMT";
static const char* testdate_1_log = "[24/Oct/2013:00:11:57 +0000]";
static const char* testdate_1_iso = "20131024001157";

static const char* testdate_2_in = "Fri, 12 Apr 2013 00:31:11 GMT";
static const char* testdate_2_out = "Fri, 12 Apr 2013 00:31:11 GMT";
static const char* testdate_2_log = "[12/Apr/2013:00:31:11 +0000]";
static const char* testdate_2_iso = "20130412003111";

static const char* testdate_3_in = "Thu Oct 24 00:11:57 2013";
static const char* testdate_3_out = "Thu, 24 Oct 2013 00:11:57 GMT";

static const char* testdate_4_in = "Fri, 12-Apr-13 00:31:11 GMT";
static const char* testdate_4_out = "Fri, 12 Apr 2013 00:31:11 GMT";

static const char* testdate_5_in = "Sun, 06 Nov 1994 08:49:37 GMT";  // RFC 822, updated by RFC 1123
static const char* testdate_5_out = "Sun, 06 Nov 1994 08:49:37 GMT";

static const char* testdate_6_in = "Sunday, 06-Nov-94 08:49:37 GMT"; // RFC 850, obsoleted by RFC 1036
static const char* testdate_6_out = "Sun, 06 Nov 1994 08:49:37 GMT";

static const char* testdate_7_in = "Sun Nov  6 08:49:37 1994";       // ANSI C's asctime() format
static const char* testdate_7_out = "Sun, 06 Nov 1994 08:49:37 GMT";


class test_http_date : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_http_date);
    CPPUNIT_TEST(test_date_1);
    CPPUNIT_TEST(test_date_2);
    CPPUNIT_TEST(test_date_3);
    CPPUNIT_TEST(test_date_4);
    CPPUNIT_TEST(test_date_5);
    CPPUNIT_TEST(test_date_6);
    CPPUNIT_TEST(test_date_7);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_date_1()
    {
        http_date date(testdate_1_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_1_out);
        CPPUNIT_ASSERT(date.to_string(http_date_format_log) == testdate_1_log);
        CPPUNIT_ASSERT(date.to_string(http_date_format_iso) == testdate_1_iso);
    }

    void test_date_2()
    {
        http_date date(testdate_2_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_2_out);
        CPPUNIT_ASSERT(date.to_string(http_date_format_log) == testdate_2_log);
        CPPUNIT_ASSERT(date.to_string(http_date_format_iso) == testdate_2_iso);
    }

    void test_date_3()
    {
        http_date date(testdate_3_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_3_out);
    }

    void test_date_4()
    {
        http_date date(testdate_4_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_4_out);
    }

    void test_date_5()
    {
        http_date date(testdate_5_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_5_out);
    }

    void test_date_6()
    {
        http_date date(testdate_6_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_6_out);
    }

    void test_date_7()
    {
        http_date date(testdate_7_in);
        CPPUNIT_ASSERT(date.to_string() == testdate_7_out);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_http_date::suite());
    runner.run(controller);
    outputer.write();
    
    return 0;
}
