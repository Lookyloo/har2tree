[![Build Status](https://travis-ci.org/viper-framework/har2tree.svg?branch=master)](https://travis-ci.org/viper-framework/har2tree)
[![codecov](https://codecov.io/gh/viper-framework/har2tree/branch/master/graph/badge.svg)](https://codecov.io/gh/viper-framework/har2tree)

Har2Tree
========


This package generate a tree out of a HAR dump.


Installation
============

The core dependency is ETE Toolkit, which you can install following the guide
on the official website: http://etetoolkit.org/download/

Note: if you don't want to export the tree to an image using PyQt4, no need to do the
virtualenv magic.

Protip
======

If you like using virtualenv and have `pew` installed you can also do it this way:

```
sudo apt-get install python-qt4
pip install -r requirements.txt
pew toggleglobalsitepackages  # PyQt4 is not easily installable in a virtualenv
pip install -e .
```
