#!/usr/bin/env bash

if [ -d "./build-project"]
then
	mkdir --parents -verbose "./build-project"
fi

cd "./build-project"
cmake ..
make .
