//
//  test_resolver.cc
//

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>

#include "log.h"
#include "io.h"
#include "socket.h"
#include "resolver.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>

class test_resolver : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_resolver);
    CPPUNIT_TEST(test_resolve_localhost_1_ok);
    CPPUNIT_TEST(test_resolve_localhost_2_ok);
    CPPUNIT_TEST(test_resolve_hostname_ok);
    CPPUNIT_TEST(test_resolve_unknwonhost_4_err);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_resolve_localhost_1_ok()
    {
        resolver dns;
        socket_addr addr;
        bool result = dns.lookup(addr, "localhost:80");
        CPPUNIT_ASSERT(result == true);
        CPPUNIT_ASSERT(socket_addr::addr_to_string(addr) == "127.0.0.1:80");
        CPPUNIT_ASSERT(addr.ip4addr.sin_port  == htons(80));
    }

    void test_resolve_localhost_2_ok()
    {
        resolver dns;
        socket_addr addr;
        bool result = dns.lookup(addr, "localhost", 81);
        CPPUNIT_ASSERT(result == true);
        CPPUNIT_ASSERT(socket_addr::addr_to_string(addr) == "127.0.0.1:81");
        CPPUNIT_ASSERT(addr.ip4addr.sin_port  == htons(81));
    }

    void test_resolve_hostname_ok()
    {
        resolver dns;
        socket_addr addr;
        char hostname[256];
        memset(hostname, 0, sizeof(hostname));
        int ret = gethostname(hostname, sizeof(hostname)-1);
        CPPUNIT_ASSERT(ret == 0);
        bool result = dns.lookup(addr, hostname, 443);
        CPPUNIT_ASSERT(result == true);
        CPPUNIT_ASSERT(socket_addr::addr_to_string(addr) == "127.0.0.1:443");
        CPPUNIT_ASSERT(addr.ip4addr.sin_port  == htons(443));
    }

    void test_resolve_unknwonhost_4_err()
    {
        resolver dns;
        socket_addr addr;
        bool result = dns.lookup(addr, "unknown.host");
        CPPUNIT_ASSERT(result == false);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_resolver::suite());
    runner.run(controller);
    outputer.write();
}
