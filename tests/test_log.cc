//
//  test_log.cc
//

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <ctime>
#include <string>
#include <vector>
#include <queue>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>

#include "io.h"
#include "log.h"
#include "queue_atomic.h"
#include "log_thread.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>

using namespace std::chrono;


/* test_log_thread */

struct test_log_thread
{
    log_thread &logger;
    const size_t items_per_thread;
    std::thread thread;
    
    test_log_thread(log_thread &logger, const size_t items_per_thread)
        : logger(logger), items_per_thread(items_per_thread), thread(&test_log_thread::mainloop, this) {}
    
    void mainloop()
    {
        for (size_t i = 0; i < items_per_thread; i++) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%lu\n", i);
            time_t current_time = time(nullptr);
            logger.log(current_time, buf);
        }
        
        // wait 30 milliseconds
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
};

/* test_log */

static const char* tmp_tmpl = "/tmp/test_log.XXXXXX";

class test_log : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_log);
    CPPUNIT_TEST(test_log_thread_1);
    CPPUNIT_TEST_SUITE_END();
    
public:
    
    void setUp() {}
    void tearDown() {}
    
    void test_log_thread_1()
    {
        char tmp_fname[FILENAME_MAX];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);

        /* start logger thread */
        log_thread logger(fd, 65536);
        
        /* start log producer thread */
        test_log_thread log_test(logger, 32768);
        
        /* shutdown threads */
        log_test.thread.join();
        logger.shutdown();
        
        /* close fd */
        close(fd);
        
        FILE *file = fopen(tmp_fname, "r");
        CPPUNIT_ASSERT(file != nullptr);
        for (size_t i = 0; i < 1024; i++) {
            char buf[16];
            char *line = fgets(buf, sizeof(buf), file);
            CPPUNIT_ASSERT(line != nullptr);
            size_t s;
            CPPUNIT_ASSERT(sscanf(line, "%lu", &s) == 1);
            CPPUNIT_ASSERT(s == i);
        }
        fclose(file);
        unlink(tmp_fname);
    }
};

int main(int argc, const char * argv[])
{
    CppUnit::TestResult controller;
    CppUnit::TestResultCollector result;
    CppUnit::TextUi::TestRunner runner;
    CppUnit::CompilerOutputter outputer(&result, std::cerr);
    
    controller.addListener(&result);
    runner.addTest(test_log::suite());
    runner.run(controller);
    outputer.write();
}
