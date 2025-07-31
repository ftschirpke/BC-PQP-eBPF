#!/bin/sh

cd "$(dirname $0)"

./load.sh $1
echo "watching logs"
./logs.sh
