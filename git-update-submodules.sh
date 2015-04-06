#!/bin/sh
git submodule update --init --recursive
cp CMakeLists.txt.cppunit third_party/cppunit/CMakeLists.txt
