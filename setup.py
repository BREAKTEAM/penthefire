#!/usr/bin/env python

from setuptools import setup

setup(
    name='penthefire',
    version='1.1',
    description=
    'Security tool implementing attacks test the resistance of firewall',
    author='BreakTeam',
    author_email='aishee@break.team',
    url='https://github.com/BREAKTEAM/penthefire',
    scripts=['wolff'],
    packages=['penthefire'],
    package_dir={'penthefire': 'utils'},
    provides=['penthefire'],
    requires=['scapy', 'argparse', 'ftplib'],
    classifiers=[
        'Development Status :: 2 Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: No licenses',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: System :: Networking :: Firewalls',
    ],
)
