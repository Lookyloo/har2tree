#!/usr/bin/env python3
from setuptools import setup


setup(
    name='har2tree',
    version='1.14-dev',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/Lookyloo/har2tree',
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
    test_suite="tests",
    install_requires=['ete3', 'six', 'beautifulsoup4', 'lxml']
)
