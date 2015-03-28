# Latypus

a modern, portable and scalable high performance C++1y m:n threaded HTTP client and server

## Overview
  * Supports Linux, FreeBSD and Mac OS X
  * Hybrid message/event driven m:n threaded protocol agnostic state machine
  * Scalable event driven protocol threads (kqueue, epoll, poll, select)
  * protocol state labels assigned to threads. e,g, router,worker,keepalive,linger
  * protocol states can be assigned to single thread to emulate event driven servers like Node.js
  * protocol states can be assigned to many threads to emulate m:n threaded event driven servers
  * protocol states can be distributed between threads i.e. router,listener and n worker threads
  * protocol states have an associated coroutine
  * pipes or unix sockets are used to route connections between threads

## Third Party Dependencies
  * [cppunit](http://www.freedesktop.org/wiki/Software/cppunit/)
  * [boringssl](https://boringssl.googlesource.com/boringssl/)
  * [libssh](https://www.libssh.org/) (soon)
  * [wrk](https://github.com/wg/wrk/) (soon)

### Submodules
  * Fetching
````
git submodule update --init --recursive
````
  * Updating
````
git submodule foreach git pull
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

### Windows
  * python, perl, yasm, ninja, CMake

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
  * CMake ninja on Windows (Windows support in progress)
````
"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" amd64
mkdir build
cd build
cmake -G "Ninja" ..
ninja
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
