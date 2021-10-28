# Latypus

a modern, portable and scalable high performance C++1y m:n threaded HTTP client and server

**NOTE:** latypus is currently **experimental**

## Overview
  * Supports Linux, FreeBSD and Mac OS X
  * Supports TLS, TLS Server Name Extension
  * Scalable event driven protocol threads (kqueue, epoll, poll)
  * Hybrid message/event driven m:n threaded protocol agnostic state machine
  * protocol states assigned to threads. e,g, listener, router, worker, keepalive
  * protocol states can be assigned to a single thread to emulate event driven servers like Node.js
  * protocol states can be assigned to multiple threads to emulate m:n threaded event driven servers
  * protocol states can be distributed among threads i.e. one listener, one router and n workers

## Screenshot
![Screenshot of latypus](https://raw.githubusercontent.com/metaparadigm/latypus/master/screenshot.png)

## Third Party Dependencies
  * [cppunit](http://www.freedesktop.org/wiki/Software/cppunit/)

## Example
Example http echo server
```c++
#include "latypus.h"

int main(int argc, const char * argv[])
{
    struct echo_fn {
        std::string operator()(http_server_connection *conn) {
            return std::string("echo ") + conn->request.get_request_path();
        }
    };
    
    protocol_engine engine;
    auto cfg = engine.default_config<http_server>();
    engine.bind_function<http_server>(cfg, "/echo", echo_fn());
    engine.run();
    engine.join();
    
    return 0;
}
```

## Applications

 * `neta` - http application server
 * `netb` - http benchmarking tool
 * `netc` - http client
 * `netd` - http server

## Submodules
  * Fetching
````
sh git-update-submodules.sh
````

## Configuration
### TLS
  * To enable experimental TLS support, add the following to netd.cfg
  * NOTE: tls_cert_file can point to either a server certificate or to a chain file which contains the PEM format server certificate first followed by any intermediate certificates in PEM format.
````
tls_key_file          /path_to_key/key.pem;
tls_cert_file         /path_to_cert/cert.pem;

proto_listener        http_server 8443 tls;           /* ipv4 ip addr any TLS */
````

## Build Dependencies
### Debian
  * Tested with Debian 8, Clang 3.5, Ragel 6.8
````
sudo apt-get install ragel cmake clang clang++ libc++-dev valgrind google-perftools
````

### FreeBSD
  * Tested with FreeBSD 10.0, Clang 3.5, Ragel 6.9
````
pkg install cmake gmake ragel
````

### Mac OS X
  * Tested with Xcode 6.1.1, Clang 3.5, Ragel 6.8
````
brew install cmake ragel
````

## Building
  * GNU Makefile build on Linux, Mac OS X
````
make -j8
````
  * Security hardened build with gcc
````
make prefer_gcc=1 enable_harden=1 -j8
````
  * GNU Makefile build on FreeBSD
````
gmake -j8
````
  * CMake build on FreeBSD, Ubuntu, Debian, Mac OS X
````
mkdir build
cd build
CC=$(which clang) CXX=$(which clang++) cmake -DCMAKE_BUILD_TYPE=Release ..
````
  * CMake XCode project on Mac OS X
````
mkdir build
cd build
cmake -G Xcode..
````

## Running

  * Architecture build directories
    * Linux - ````build/linux_x86_64/bin````
    * Mac OS X - ````build/darwin_x86_64/bin````
    * FreeBSD - ````build/freebsd_amd64/bin````

  * server
````
./build/<arch>/bin/netd --config config/netd.cfg
````
  * client
````
./build/<arch>/bin/netc -O http://127.0.0.1:8080/index.html
````
  * benchmark tool
````
./build/<arch>/bin/netb -n 300000 -k 1000 -c 500  http://127.0.0.1:8080/index.html
````
  * application
````
./build/<arch>/bin/neta
````

## Benchmarking

  * Benchmarking with [wrk - a Modern HTTP benchmarking tool](https://github.com/wg/wrk)
  * Download build and install wrk benchmark tool (Debian/Ubuntu)
````
sudo apt-get install build-essential
sudo apt-get install libssl-dev
sudo apt-get install git
git clone https://github.com/wg/wrk.git
cd wrk
make
````

  * Install wrk benchmark tool (Mac OS X)
````
brew install wrk
````

  * Benchmarking with wrk: 8 threads, 5000 connections for 10 seconds
````
wrk -t8 -c5000 -d10s http://127.0.0.1:8080/index.html
````

### Linux Performance Tuning for C100K

  * /etc/sysctl.conf
````
fs.file-max = 500000
net.ipv4.ip_local_port_range = 8192 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
````

  * /etc/security/limits.conf
````
root             soft    nofile          250000
root             hard    nofile          250000
````

## Testing

### Testing with Google Performance Tools
  * Documentation
    * [gperftools project](https://code.google.com/p/gperftools/)
    * [gperftools cpu profiling documentation](http://gperftools.googlecode.com/svn/trunk/doc/cpuprofile.html)

  * Installing gperftools (Debian/Ubuntu)
````
sudo apt-get install google-perftools
````

  * Start server
````
LD_PRELOAD=/usr/lib/libprofiler.so.0 \
CPUPROFILESIGNAL=12 CPUPROFILE=/tmp/prof.out \
./build/linux_x86_64/bin/netd
````
  * Run tests
````
killall -12 netd
wrk -t8 -c5000 -d10s http://127.0.0.1:8080/index.html
killall -12 netd
````
  * Read results
````
google-pprof -text -cum ./build/linux_x86_64/bin/netd /tmp/prof.out.0
google-pprof -pdf ./build/linux_x86_64/bin/netd /tmp/prof.out.0 > /tmp/prof.out.0.pdf
````

### Testing with valgrind
  * [Valgrind Documentation](http://valgrind.org/docs/)
````
valgrind ./build/linux_x86_64/bin/netd
````

### Testing with Clang AddressSanitizer
  * [Clang AddressSanitizer Documentation](http://clang.llvm.org/docs/AddressSanitizer.html)
  * Build with -fsanitize=address
 ````
make -j8 sanitize=address
ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.5 ./build/linux_x86_64/bin/netd
````

### Testing with Clang MemorySanitizer
  * [Clang MemorySanitizer Documentation](http://clang.llvm.org/docs/ThreadSanitizer.html)
  * Build with -fsanitize=memory
````
make -j8 sanitize=memory
MSAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.5 ./build/linux_x86_64/bin/netd
````

### Testing with Clang ThreadSanitizer
  * [Clang ThreadSanitizer Documentation](http://clang.llvm.org/docs/ThreadSanitizer.html)
  * Build with -fsanitize=thread
````
make -j8 sanitize=thread
TSAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.5 ./build/linux_x86_64/bin/netd
````

### Testing with Clang Undefined Behavior Sanitizer
  * [Clang Undefined Behavior Sanitizer](http://blog.llvm.org/2013/04/testing-libc-with-fsanitizeundefined.html)
  * Build with -fsanitize=undefined
````
make -j8 sanitize=undefined
./build/linux_x86_64/bin/netd
````
