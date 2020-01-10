#!/bin/bash
cd `dirname $0`
chmod a+x configure
time ./configure --prefix=`pwd`/build
