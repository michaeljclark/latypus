//
//  test_url.cc
//

#include <cstdio>
#include <cstdint>
#include <string>
#include <iostream>
#include <iomanip>
#include <memory>
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
    CPPUNIT_TEST(test_url_map_2);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_url_map_1()
    {
        trie<uint32_t> url_map;

        url_map.insert("/", 1);
        url_map.insert("/bar/", 2);
        url_map.insert("/foo/", 3);
        url_map.insert("/foo/bar/", 4);
        url_map.insert("/foo/bang/", 5);
        url_map.insert("/woo/tang/", 6);
        url_map.insert("/woo/tang/", 6);

        CPPUNIT_ASSERT(url_map.find_nearest("/bar").second == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/bar/bang").second == 2);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo").second == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/woo").second == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/baz").second == 4);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bar/bart").second == 4);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang").second == 3);
        CPPUNIT_ASSERT(url_map.find_nearest("/foo/bang/").second == 5);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang").second == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/bar").second == 6);
        CPPUNIT_ASSERT(url_map.find_nearest("/woo/tang/baz").second == 6);
    }

    void test_url_map_2()
    {
        trie<uint32_t> url_map;
        
        url_map.insert("/", 1);
        url_map.insert("/func/", 2);

        CPPUNIT_ASSERT(url_map.find_nearest("/bar").second == 1);
        CPPUNIT_ASSERT(url_map.find_nearest("/func/").second == 2);
        CPPUNIT_ASSERT(url_map.find_nearest("/favicon.ico").second == 0);
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
