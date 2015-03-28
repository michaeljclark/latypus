//
//  io.h
//

#ifndef io_h
#define io_h

struct stat;

struct io_file;
struct io_reader;
struct io_writer;
struct io_buffer;

typedef std::shared_ptr<io_file> io_file_ptr;
typedef std::shared_ptr<io_reader> io_reader_ptr;
typedef std::shared_ptr<io_writer> io_writer_ptr;
typedef std::shared_ptr<io_buffer> io_buffer_ptr;


/* io_error */

struct io_error
{
    int errcode;
    
    io_error() : errcode(0) {}
    io_error(const int errcode) : errcode(errcode) {}
    
    std::string to_string() const { return strerror(errcode); }
};


/* io_result */

struct io_result : std::pair<const ssize_t,const io_error>
{
    io_result(const ssize_t size) : std::pair<const ssize_t,const io_error>(size, io_error()) {}
    io_result(const io_error &error) : std::pair<const ssize_t,const io_error>(0, error) {}
    io_result(const io_result &o) : std::pair<const ssize_t,const io_error>(o.first, o.second) {}
    
    const ssize_t& size() const { return first; }
    const io_error& error() const { return second; }
    const bool has_error() const { return second.errcode != 0; }
    std::string error_string() const { return second.to_string(); }
};


/* io_reader */

struct io_reader
{
    virtual ~io_reader() {};
    
    virtual io_result read(void *buf, size_t len) = 0;
    virtual io_result readv(const struct iovec *iov, int iovcnt) = 0;
};


/* io_writer */

struct io_writer
{
    virtual ~io_writer() {};
    
    virtual io_result write(void *buf, size_t len) = 0;
    virtual io_result writev(const struct iovec *iov, int iovcnt) = 0;
};


/* io_seekable */

struct io_seekable
{
    virtual ~io_seekable() {};
    
    virtual size_t offset() const = 0;
    virtual void set_offset(size_t offset) = 0;
};


/* io_file_name */

struct io_file_name : std::pair<std::string,io_error>
{
    io_file_name(std::string name) : std::pair<std::string,io_error>(name,io_error()) {}
    io_file_name(io_error error) : std::pair<std::string,io_error>(std::string(),error) {}

    const std::string& name() const { return first; }
    const io_error& error() const { return second; }
};


/* io_file */

struct io_file: io_reader, io_writer, io_seekable
{
    off_t file_offset;
    int fd;
    
    io_file();
    io_file(int fd);
    virtual ~io_file();
    
    int get_fd();
    void set_fd(int new_fd);
    int release_fd();
    void close();
    io_file_name name();
    io_error stat(struct stat &stat_result);

    static io_error stat(std::string filename, struct stat &stat_result);

    io_error open(std::string filename, int flags, int mode = 0644);

    size_t offset() const { return file_offset; }
    void set_offset(size_t offset) { file_offset = offset; }
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
};


/* io_buffer */

struct io_buffer: io_reader, io_writer, io_seekable
{
    std::vector<char>       buffer;
    size_t                  buffer_length;
    size_t                  buffer_offset;

    io_buffer();
    virtual ~io_buffer();
    
    void resize(size_t size);
    void clear();
    void reset();
    void set(const char* src, size_t len);
    
    io_result buffer_read(io_reader &reader);
    io_result buffer_write(io_writer &writer);
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
    
    char* data() { return buffer.data(); }
    char* pos() { return buffer.data() + buffer_offset; }
    size_t size() const { return buffer.size(); }
    size_t length() const { return buffer_length; }
    size_t offset() const { return buffer_offset; }
    size_t bytes_readable() const { return buffer_length - buffer_offset; }
    size_t bytes_writable() const { return buffer.size() - buffer_length; }
    void set_length(size_t length) { assert(length <= buffer.size()); buffer_length = length; }
    void set_offset(size_t offset) { assert(offset <= buffer.size()); buffer_offset = offset; }
};


/* io_ring_buffer */

struct io_ring_buffer: io_reader, io_writer
{
    std::vector<char>       buffer;
    ssize_t                 back;
    ssize_t                 front;
    ssize_t                 mask;
    
    io_ring_buffer();
    virtual ~io_ring_buffer();
    
    void resize(size_t size);
    void clear();
    void reset();
    void set(const char* src, size_t len);
    
    io_result buffer_read(io_reader &reader);
    io_result buffer_write(io_writer &writer);
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
    
    char* data() { return buffer.data(); }
    char* pos() { return buffer.data() + (back & mask); }
    size_t size() const { return buffer.size(); }
    size_t bytes_readable() const { return (ssize_t)buffer.size() - front + back; }
    size_t bytes_writable() const { return front - back; }
};


/* io_buffered_reader */

struct io_buffered_reader : io_reader
{
    const size_t            default_size = 4096;
    
    io_buffer_ptr           buffer;
    io_reader_ptr           reader;
    
    io_buffered_reader(io_reader_ptr reader);
    io_buffered_reader(io_buffer_ptr buffer, io_reader_ptr reader);

    void set_buffer(io_buffer_ptr buffer);
    void set_reader(io_reader_ptr reader);
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
};


/* io_buffered_writer */

struct io_buffered_writer : io_writer
{
    const size_t            default_size = 4096;
    
    io_buffer_ptr           buffer;
    io_writer_ptr           writer;
    
    io_buffered_writer(io_writer_ptr writer);
    io_buffered_writer(io_buffer_ptr buffer, io_writer_ptr writer);
    virtual ~io_buffered_writer();
    
    void set_buffer(io_buffer_ptr buffer);
    void set_writer(io_writer_ptr writer);
    
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
    io_result flush();
};

#endif
