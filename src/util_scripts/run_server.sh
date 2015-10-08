#!/bin/bash

app="$(dirname $(readlink -f $0))"

source $app/virtual_env/bin/activate
python3 $app/src/DummyApplication.py
