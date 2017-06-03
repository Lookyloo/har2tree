#!/bin/bash

set -e
set -x


pip install -U -r requirements.txt
pip install -U nose coverage
# On a new pew env:
# pew toggleglobalsitepackages
nosetests --with-coverage --cover-package=har2tree tests/test.py
