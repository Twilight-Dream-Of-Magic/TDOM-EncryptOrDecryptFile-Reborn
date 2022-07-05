#!/usr/bin/env bash

# --parents

if [ -d "./build-project"];
then
	mkdir --verbose "./build-project"
fi

cd "./build-project"
cmake ../CMakeLists.txt
make .
