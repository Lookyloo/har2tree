#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup  # type: ignore


setup(
    name='har2tree',
    version='1.0',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/viper-framework/har2tree',
    description='HAR to ETE tree.',
    packages=['har2tree'],
    scripts=['bin/har2tree'],
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
    test_suite="tests",
    include_package_data=True,
    package_data={'har2tree': ['data/img/*.png']},
    install_requires=['ete3', 'six', 'beautifulsoup4', 'lxml']
)
