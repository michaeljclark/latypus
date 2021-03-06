//
//  io.cc
//

#include "plat_os.h"

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "io.h"
#include "bits.h"
#include "log.h"


/* io_file */

#if USE_PREAD_PWRITE
io_file::io_file() : file_offset(0), fd(-1) {}
io_file::io_file(int fd) : file_offset(0), fd(fd) {}
#else
io_file::io_file() : fd(-1) {}
io_file::io_file(int fd) : fd(fd) {}
#endif

io_file::~io_file()
{
    close();
}

io_error io_file::open(std::string filename, int flags, int mode)
{
    close();
    fd = ::open(filename.c_str(), flags, mode);
    return io_error(fd < 0 ? errno : 0);
}

#if USE_PREAD_PWRITE

size_t io_file::offset() const { return file_offset; }

void io_file::set_offset(size_t offset) { file_offset = offset; }

#else

size_t io_file::offset() const { return lseek(fd, 0, SEEK_CUR); }

void io_file::set_offset(size_t offset) { lseek(fd, offset, SEEK_SET); }

#endif

io_result io_file::read(void *buf, size_t len)
{
#if USE_PREAD_PWRITE
    ssize_t ret = ::pread(fd, buf, len, file_offset);
#else
    ssize_t ret = ::read(fd, buf, len);
#endif
    if (ret < 0) {
        return io_result(errno);
    }
#if USE_PREAD_PWRITE
    file_offset += ret;
#endif
    return io_result(ret);
}

io_result io_file::write(void *buf, size_t len)
{
#if USE_PREAD_PWRITE
    ssize_t ret = ::pwrite(fd, buf, len, file_offset);
#else
    ssize_t ret = ::write(fd, buf, len);
#endif
    if (ret < 0) {
        return io_result(errno);
    }
#if USE_PREAD_PWRITE
    file_offset += ret;
#endif
    return io_result(ret);
}

int io_file::get_fd()
{
    return fd;
}

void io_file::set_fd(int new_fd)
{
    close();
    fd = new_fd;
}

int io_file::release_fd()
{
    int old_fd = fd;
    close();
    return old_fd;
}

void io_file::close()
{
    if (fd >= 0) {
        ::close(fd);
#if USE_PREAD_PWRITE
        file_offset = 0;
#endif
        fd = -1;
    }
}

io_file_name io_file::name()
{
#if 0
    char path[MAXPATHLEN];
    if (fd < 0) {
        return io_file_name(io_error(EINVAL));
    }
    if (::fcntl(fd, F_GETPATH, path) < 0) {
        return io_file_name(io_error(errno));
    }
    return io_file_name(path);
#else
    return io_file_name(io_error(EINVAL));
#endif
}

io_error io_file::stat(struct stat &stat_result)
{
    memset(&stat_result, 0, sizeof(stat_result));
    if (fd < 0) {
        return io_error(EINVAL);
    }
    if (::fstat(fd, &stat_result) < 0) {
        return io_error(errno);
    } else {
        return io_error();
    }
}

io_error io_file::stat(std::string filename, struct stat &stat_result)
{
    memset(&stat_result, 0, sizeof(stat_result));
    if (::stat(filename.c_str(), &stat_result) < 0) {
        return io_error(errno);
    } else {
        return io_error();
    }
}


/* io_buffer */

io_buffer::io_buffer() : buffer(), buffer_length(0), buffer_offset(0) {}

io_buffer::~io_buffer() {}

void io_buffer::resize(size_t size)
{
    size_t buffer_size = roundpow2(size);
    if (size != buffer_size) {
        log_debug("%s rounding buffer size from %lu to %lu", __func__, size, buffer_size);
    }
    buffer.resize(buffer_size);
}

void io_buffer::clear()
{
    buffer_offset = buffer_length = 0;
    if (buffer.size() > 0) {
        memset(&buffer[0], 0, buffer.size());
    }
}

void io_buffer::reset()
{
    buffer_offset = buffer_length = 0;
}

void io_buffer::set(const char* src, size_t len)
{
    assert(len <= buffer.size());
    buffer_offset = 0;
    buffer_length = len;
    if (src >= buffer.data() && src < buffer.data() + len) {
        memmove(buffer.data(), src, len);
    } else {
        memcpy(buffer.data(), src, len);
    }
}

io_result io_buffer::read(void *buf, size_t len)
{
    ssize_t read_max = bytes_readable();
    size_t bytes_to_read = len < (size_t)read_max ? len : read_max;

    if (read_max < 0 || len == 0) return io_result(0);

    memcpy(buf, buffer.data() + buffer_offset, bytes_to_read);
    buffer_offset += bytes_to_read;
    
    return io_result(bytes_to_read);
}

io_result io_buffer::write(void *buf, size_t len)
{
    ssize_t write_max = bytes_writable();
    size_t bytes_to_write = len < (size_t)write_max ? len : write_max;
    
    if (write_max < 0 || len == 0) return io_result(0);
    
    memcpy(buffer.data() + buffer_offset, buf, bytes_to_write);
    buffer_length += bytes_to_write;

    return io_result(bytes_to_write);
}

io_result io_buffer::buffer_read(io_reader &reader)
{
    ssize_t bytes_to_read = bytes_writable();

    if (bytes_to_read <= 0) return io_result(0);

    io_result result = reader.read(buffer.data() + buffer_offset, bytes_to_read);
    buffer_length += result.size();
    
    return result;
}

io_result io_buffer::buffer_write(io_writer &writer)
{
    ssize_t bytes_to_write = bytes_readable();
    
    if (bytes_to_write <= 0) return io_result(0);

    io_result result = writer.write(buffer.data() + buffer_offset, bytes_to_write);
    buffer_offset += result.size();
    
    return result;
}


/* io_ring_buffer */

io_ring_buffer::io_ring_buffer() : buffer(), back(0), front(0) {}

io_ring_buffer::~io_ring_buffer() {}

void io_ring_buffer::resize(size_t size)
{
    size_t buffer_size = roundpow2(size);
    if (size != buffer_size) {
        log_debug("%s rounding buffer size from %lu to %lu", __func__, size, buffer_size);
    }
    
    buffer.resize(buffer_size);
    back = 0;
    mask = buffer_size - 1;
    front = buffer.size();
}

void io_ring_buffer::clear()
{
    back = 0;
    front = buffer.size();
    if (buffer.size() > 0) {
        memset(&buffer[0], 0, buffer.size());
    }
}

void io_ring_buffer::reset()
{
    back = 0;
    front = buffer.size();
}

void io_ring_buffer::set(const char* src, size_t len)
{
    assert(len <= buffer.size());
    back = len;
    front = buffer.size();
    if (src >= buffer.data() && src < buffer.data() + len) {
        memmove(buffer.data(), src, len);
    } else {
        memcpy(buffer.data(), src, len);
    }
}

io_result io_ring_buffer::read(void *buf, size_t len)
{
    size_t read_max = bytes_readable();
    size_t read_offset = front & mask;
    size_t bytes_to_read = std::min(len, read_max);
    
    if (bytes_to_read == 0) return io_result(0);

    ssize_t len1 = buffer.size() - read_offset;
    if (len1 > 0) {
        memcpy((unsigned char*)buf, buffer.data() + read_offset, len1);
    }
    
    ssize_t len2 = bytes_to_read - len1;
    if (len2 > 0) {
        memcpy((unsigned char*)buf + len1, buffer.data(), len2);
    }
    
    front += bytes_to_read;
    
    return io_result(bytes_to_read);
}

io_result io_ring_buffer::write(void *buf, size_t len)
{
    size_t write_max = bytes_writable();
    size_t write_offset = back & mask;
    size_t bytes_to_write = std::min(len, write_max);
    
    if (bytes_to_write == 0) return io_result(0);

    ssize_t len1 = buffer.size() - write_offset;
    if (len1 > 0) {
        memcpy(buffer.data() + write_offset, (unsigned char*)buf, len1);
    }

    ssize_t len2 = bytes_to_write - len1;
    if (len2 > 0) {
        memcpy(buffer.data(), (unsigned char*)buf + len1, len2);
    }
    
    back += bytes_to_write;
    
    return io_result(bytes_to_write);
}

io_result io_ring_buffer::buffer_read(io_reader &reader)
{
    size_t read_max = bytes_writable();
    size_t write_offset = back & mask;
    size_t bytes_to_read = std::min(buffer.size() - write_offset, read_max);
    
    if (bytes_to_read == 0) return io_result(0);
    
    io_result result = reader.read(buffer.data() + write_offset, bytes_to_read);
    back += result.size();
    
    return result;
}

io_result io_ring_buffer::buffer_write(io_writer &writer)
{
    size_t write_max = bytes_readable();
    size_t read_offset = front & mask;
    size_t bytes_to_write = std::min(buffer.size() - read_offset, write_max);
    
    if (bytes_to_write == 0) return io_result(0);
    
    io_result result = writer.write(buffer.data() + read_offset, bytes_to_write);
    front += result.size();
    
    return result;
}


/* io_buffered_reader */

io_buffered_reader::io_buffered_reader(io_buffer_ptr buffer, io_reader_ptr reader) : buffer(buffer), reader(reader) {}

io_buffered_reader::io_buffered_reader(io_reader_ptr reader) : reader(reader)
{
    buffer = std::make_shared<io_buffer>();
    buffer->resize(default_size);
}

void io_buffered_reader::set_buffer(io_buffer_ptr buffer)
{
    this->buffer = buffer;
}

void io_buffered_reader::set_reader(io_reader_ptr reader)
{
    this->reader = reader;
}

io_result io_buffered_reader::read(void *buf, size_t len)
{
    if (buffer->bytes_readable() == 0) {
        io_result res = buffer->buffer_read(*reader);
        if (res.has_error()) return res;
    }
    return buffer->read(buf, len);
}


/* io_buffered_writer */

io_buffered_writer::io_buffered_writer(io_buffer_ptr buffer, io_writer_ptr writer) : buffer(buffer), writer(writer) {}

io_buffered_writer::io_buffered_writer(io_writer_ptr writer) : writer(writer)
{
    buffer = std::make_shared<io_buffer>();
    buffer->resize(default_size);
}

io_buffered_writer::~io_buffered_writer()
{
    flush();
}

void io_buffered_writer::set_buffer(io_buffer_ptr buffer)
{
    this->buffer = buffer;
}

void io_buffered_writer::set_writer(io_writer_ptr writer)
{
    this->writer = writer;
}

io_result io_buffered_writer::write(void *buf, size_t len)
{
    io_result res = buffer->write(buf, len);
    if (res.has_error()) return res;
    if (buffer->bytes_readable() == buffer->size()) {
        io_result res = buffer->buffer_write(*writer);
        if (res.has_error()) return res;
    }
    return res;
}

io_result io_buffered_writer::flush()
{
    if (buffer->bytes_readable() > 0) {
        io_result res = buffer->buffer_write(*writer);
        if (res.has_error()) return res;
    }
    return io_result(0);
}
