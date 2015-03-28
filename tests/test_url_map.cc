//
//  test_url.cc
//

#include <cstdio>
#include <cstdint>
#include <string>
#include <iostream>
#include <memory>
#include <map>

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
        typedef std::map<std::string,uint32_t> map_type;
        typedef std::pair<std::string,uint32_t> pair_type;
        map_type map;
        
        map.insert(pair_type("/bar/", 1));
        map.insert(pair_type("/foo/", 1));
        map.insert(pair_type("/foo/bar/", 1));
        map.insert(pair_type("/foo/bang/", 1));
        
        auto i_1 = map.lower_bound("/bar/bang");
        auto i_2 = map.upper_bound("/bar/bang");
        auto i_3 = map.lower_bound("/foo/baz");
        auto i_4 = map.upper_bound("/foo/baz");
        auto i_5 = map.lower_bound("/foo/bang/boo");
        auto i_6 = map.upper_bound("/foo/bang/bar");
        
        if (i_1 != map.end()) printf("i1_ %s\n", i_1->first.c_str());
        if (i_2 != map.end()) printf("i2_ %s\n", i_2->first.c_str());
        if (i_3 != map.end()) printf("i3_ %s\n", i_3->first.c_str());
        if (i_4 != map.end()) printf("i4_ %s\n", i_4->first.c_str());
        if (i_5 != map.end()) printf("i5_ %s\n", i_5->first.c_str());
        if (i_6 != map.end()) printf("i6_ %s\n", i_6->first.c_str());
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
