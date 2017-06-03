#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup
import har2tree


setup(
    name='har2tree',
    version=har2tree.__version__,
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/viper-framework/har2tree',
    description='HAR to ETE tree.',
    packages=['har2tree'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
    ],
    test_suite="tests"
)
