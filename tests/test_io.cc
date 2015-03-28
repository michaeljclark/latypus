//
//  test_io.cc
//

#include <unistd.h>
#include <fcntl.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

#include "plat_os.h"
#include "io.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/TestCaller.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/ui/text/TestRunner.h>


static const char* tmp_tmpl = "/tmp/test_io.XXXXXX";
static const char* test_data_1 = "0123456789ABCDEF";
static const char* test_data_2 = "xxxxxxxx";
static const char* test_data_3 = "xxxxxxxxyyyyyyyy";
static const char* test_data_4 = "yyyyyyyyxxxxxxxx";

class test_io : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(test_io);
    CPPUNIT_TEST(test_io_file_read);
    CPPUNIT_TEST(test_io_file_readv);
    CPPUNIT_TEST(test_io_file_write);
    CPPUNIT_TEST(test_io_file_writev);
    CPPUNIT_TEST(test_io_buffer_read);
    CPPUNIT_TEST(test_io_buffer_readv);
    CPPUNIT_TEST(test_io_buffer_write);
    CPPUNIT_TEST(test_io_buffer_writev);
    CPPUNIT_TEST(test_io_buffer_write_read);
    CPPUNIT_TEST(test_io_ring_buffer_read);
    CPPUNIT_TEST(test_io_ring_buffer_readv);
    CPPUNIT_TEST(test_io_ring_buffer_write);
    CPPUNIT_TEST(test_io_ring_buffer_writev);
    CPPUNIT_TEST(test_io_ring_buffer_write_read);
    CPPUNIT_TEST(test_io_ring_buffer_writev_readv_wrap);
    CPPUNIT_TEST(test_io_buffer_read_underflow);
    CPPUNIT_TEST(test_io_buffer_write_overflow);
    CPPUNIT_TEST(test_io_buffered_file_read);
    CPPUNIT_TEST(test_io_buffered_file_write);
    CPPUNIT_TEST_SUITE_END();
    
public:

    void setUp() {}
    void tearDown() {}
    
    void test_io_file_read()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using pwrite */
        ssize_t ret = pwrite(fd, test_data_1, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        
        /* read using io_file::read */
        io_file file(fd);
        io_result result = file.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file.file_offset == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
        unlink(tmp_fname);
    }

    void test_io_file_readv()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        struct iovec iov[2];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using pwrite */
        ssize_t ret = pwrite(fd, test_data_1, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        
        /* read using io_file::readv */
        io_file file(fd);
        iov[0].iov_base  = buf;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = buf + (strlen(test_data_1) >> 1);
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = file.readv(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file.file_offset == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
        unlink(tmp_fname);
    }

    void test_io_file_write()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using io_file::write */
        io_file file(fd);
        io_result result = file.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file.file_offset == strlen(test_data_1));
        
        /* read using pread */
        ssize_t ret = pread(fd, buf, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
        unlink(tmp_fname);
    }
    
    
    void test_io_file_writev()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        struct iovec iov[2];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using io_file::writev */
        io_file file(fd);
        iov[0].iov_base  = (void*)test_data_1;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = (void*)(test_data_1 + (strlen(test_data_1) >> 1));
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = file.writev(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file.file_offset == strlen(test_data_1));
        
        /* read using pread */
        ssize_t ret = pread(fd, buf, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
        unlink(tmp_fname);
    }
    
    void test_io_buffer_read()
    {
        char buf[1024];
        
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);

        buffer.set(test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        io_result result = buffer.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_buffer_readv()
    {
        char buf[1024];
        struct iovec iov[2];
        
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        buffer.set(test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        iov[0].iov_base  = buf;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = buf + (strlen(test_data_1) >> 1);
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = buffer.readv(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_buffer_write()
    {
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        io_result result = buffer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_buffer_writev()
    {
        struct iovec iov[2];

        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        iov[0].iov_base  = (void*)test_data_1;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = (void*)(test_data_1 + (strlen(test_data_1) >> 1));
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = buffer.writev(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_buffer_write_read()
    {
        char buf[1024];
        
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        io_result result1 = buffer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result1.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        io_result result2 = buffer.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result2.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_read()
    {
        char buf[1024];
        
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        buffer.set(test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        io_result result = buffer.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1040);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_readv()
    {
        char buf[1024];
        struct iovec iov[2];
        
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        buffer.set(test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        iov[0].iov_base  = buf;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = buf + (strlen(test_data_1) >> 1);
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = buffer.readv(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1040);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_write()
    {
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        io_result result = buffer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_writev()
    {
        struct iovec iov[2];
        
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        iov[0].iov_base  = (void*)test_data_1;
        iov[0].iov_len  = strlen(test_data_1) >> 1;
        iov[1].iov_base  = (void*)(test_data_1 + (strlen(test_data_1) >> 1));
        iov[1].iov_len  = strlen(test_data_1) >> 1;
        io_result result = buffer.writev(iov, 2);
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_write_read()
    {
        char buf[1024];
        
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        
        /* write to test buffer */
        io_result result1 = buffer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result1.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1024);
        CPPUNIT_ASSERT(buffer.bytes_readable() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024 - strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        io_result result2 = buffer.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result2.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.back == 16);
        CPPUNIT_ASSERT(buffer.front == 1040);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 1024);
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
    }

    void test_io_ring_buffer_writev_readv_wrap()
    {
        char buf[1024];
        struct iovec iov[2];
        
        /* initialize test buffer */
        io_ring_buffer buffer;
        buffer.resize(16);
        CPPUNIT_ASSERT(buffer.size() == 16);
        CPPUNIT_ASSERT(buffer.back == 0);
        CPPUNIT_ASSERT(buffer.front == 16);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 16);
        
        /* write to test buffer */
        iov[0].iov_base  = (void*)test_data_2;
        iov[0].iov_len  = strlen(test_data_2);
        io_result result_1 = buffer.writev(iov, 1);
        CPPUNIT_ASSERT(result_1.size() == 8);
        CPPUNIT_ASSERT(buffer.back == 8);
        CPPUNIT_ASSERT(buffer.front == 16);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 8);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 8);
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_2, strlen(test_data_2)) == 0);
        
        /* read from test buffer */
        iov[0].iov_base  = buf;
        iov[0].iov_len  = strlen(test_data_2);
        io_result result_2 = buffer.readv(iov, 1);
        CPPUNIT_ASSERT(result_2.size() == 8);
        CPPUNIT_ASSERT(buffer.back == 8);
        CPPUNIT_ASSERT(buffer.front == 24);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 0);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 16);
        CPPUNIT_ASSERT(memcmp(buf, test_data_2, strlen(test_data_2)) == 0);

        /* write to test buffer */
        iov[0].iov_base  = (void*)test_data_3;
        iov[0].iov_len  = strlen(test_data_3);
        io_result result_3 = buffer.writev(iov, 1);
        CPPUNIT_ASSERT(result_3.size() == 16);
        CPPUNIT_ASSERT(buffer.back == 24);
        CPPUNIT_ASSERT(buffer.front == 24);
        CPPUNIT_ASSERT(buffer.bytes_readable() == 16);
        CPPUNIT_ASSERT(buffer.bytes_writable() == 0);
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_4, strlen(test_data_4)) == 0);
    }
    
    void test_io_buffer_read_underflow()
    {
        char buf[12];
        
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(1024);
        CPPUNIT_ASSERT(buffer.size() == 1024);
        buffer.set(test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, strlen(test_data_1)) == 0);
        
        /* read from test buffer */
        io_result result = buffer.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result.size() == sizeof(buf));
        CPPUNIT_ASSERT(buffer.offset() == sizeof(buf));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, sizeof(buf)) == 0);
    }
    
    void test_io_buffer_write_overflow()
    {
        /* initialize test buffer */
        io_buffer buffer;
        buffer.resize(8);
        CPPUNIT_ASSERT(buffer.size() == 8);
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == 0);
        
        /* write to test buffer */
        io_result result = buffer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result.size() == buffer.size());
        CPPUNIT_ASSERT(buffer.offset() == 0);
        CPPUNIT_ASSERT(buffer.length() == buffer.size());
        CPPUNIT_ASSERT(buffer.length() != strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buffer.data(), test_data_1, buffer.size()) == 0);
    }

    void test_io_buffered_file_read()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using pwrite */
        ssize_t ret = pwrite(fd, test_data_1, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        
        /* read using io_buffered_reader::read */
        io_file_ptr file = std::make_shared<io_file>(fd);
        io_buffered_reader buffered_reader(file);
        io_result result = buffered_reader.read(buf, sizeof(buf));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file->file_offset == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
        unlink(tmp_fname);
    }
    
    void test_io_buffered_file_write()
    {
        char tmp_fname[FILENAME_MAX];
        char buf[1024];
        
        /* create temporary file */
        memcpy(tmp_fname, tmp_tmpl, sizeof(tmp_fname));
        int fd = mkstemp(tmp_fname);
        CPPUNIT_ASSERT(fd >= 0);
        
        /* write using io_buffered_writer::write */
        io_file_ptr file = std::make_shared<io_file>(fd);
        io_buffered_writer buffered_writer(file);
        io_result result = buffered_writer.write((void*)test_data_1, strlen(test_data_1));
        CPPUNIT_ASSERT(result.size() == strlen(test_data_1));
        CPPUNIT_ASSERT(file->file_offset == 0);
        buffered_writer.flush();
        CPPUNIT_ASSERT(file->file_offset == strlen(test_data_1));
        
        /* read using pread */
        ssize_t ret = pread(fd, buf, strlen(test_data_1), 0);
        CPPUNIT_ASSERT(ret == strlen(test_data_1));
        CPPUNIT_ASSERT(memcmp(buf, test_data_1, strlen(test_data_1)) == 0);
        
        /* remove temporary file */
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
    runner.addTest(test_io::suite());
    runner.run(controller);
    outputer.write();
    
    return 0;
}
