#/bin/bash
cd `dirname $0`
set -e
time make all
time make install
# result in build/jvm/openjdk-1.8.0-internal/bin
