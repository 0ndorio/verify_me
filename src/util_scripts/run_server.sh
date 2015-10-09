#!/bin/bash

app="$(dirname $(readlink -f $0))"

source $app/virtual_env/bin/activate
python $app/src/DummyApplication.py
