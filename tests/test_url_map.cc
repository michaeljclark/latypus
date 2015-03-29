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
        trie<uint32_t>::leaf_type *node;
        
        url_map.insert("/bar/", 1);
        url_map.insert("/foo/", 2);
        url_map.insert("/foo/bar/", 3);
        url_map.insert("/foo/bang/", 4);
        
        url_map.print();
        
        CPPUNIT_ASSERT(node = url_map.find_nearest_node("/bar/bang"));
        CPPUNIT_ASSERT(node->prefix == "bar/");
        CPPUNIT_ASSERT(node->val == 1);

        //CPPUNIT_ASSERT(node = url_map.find_nearest_node("/foo/woo"));
        //CPPUNIT_ASSERT(node->prefix == "foo/");
        //CPPUNIT_ASSERT(node->val == 2);

        CPPUNIT_ASSERT(node = url_map.find_nearest_node("/foo/bar/baz"));
        CPPUNIT_ASSERT(node->prefix == "r/");
        CPPUNIT_ASSERT(node->val == 3);

        CPPUNIT_ASSERT(node = url_map.find_nearest_node("/foo/bang"));
        CPPUNIT_ASSERT(node->prefix == "ng/");
        CPPUNIT_ASSERT(node->val == 4);
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
