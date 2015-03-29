//
//  test_url.cc
//

#include <cstdio>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <vector>

#include "url.h"
#include "trie.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>


class test_url_map : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_url_map);
    CPPUNIT_TEST(test_url_map_1);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_url_map_1()
    {
        trie<uint32_t> url_map;

        CPPUNIT_ASSERT(url_map.insert("/", 1) == true);
        CPPUNIT_ASSERT(url_map.insert("/bar/", 2) == true);
        CPPUNIT_ASSERT(url_map.insert("/foo/", 3) == true);
        CPPUNIT_ASSERT(url_map.insert("/foo/bar/", 4) == true);
        CPPUNIT_ASSERT(url_map.insert("/foo/bang/", 5) == true);
        CPPUNIT_ASSERT(url_map.insert("/woo/tang/", 6) == true);
        CPPUNIT_ASSERT(url_map.insert("/woo/tang/", 6) == false);

        CPPUNIT_ASSERT(url_map.find_nearest("/bar") == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/bar/bang") == 2);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo") == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/woo") == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/baz") == 4);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/bart") == 4);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang") == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang/") == 5);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang") == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/bar") == 6);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/baz") == 6);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_url_map::suite());
    runner.run(controller);
    outputer.write();
    
    return 0;
}
