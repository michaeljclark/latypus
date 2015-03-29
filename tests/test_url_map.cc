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

        url_map.insert("/bar/", 1);
        url_map.insert("/foo/", 2);
        url_map.insert("/foo/bar/", 3);
        url_map.insert("/foo/bang/", 4);
        url_map.insert("/woo/tang/", 5);
        
        url_map.print();
        
        CPPUNIT_ASSERT(url_map.find_nearest("/bar") == 0);
        CPPUNIT_ASSERT(url_map.find_nearest("/bar/bang") == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo") == 0);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/woo") == 2);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/baz") == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/bart") == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang") == 2);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang/") == 4);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang") == 0);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/bar") == 5);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/baz") == 5);
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
