#!/bin/bash

script_dir="$(dirname $(readlink -f $0))"

source $script_dir/../virtual_env/bin/activate
python -m server.src.Server
