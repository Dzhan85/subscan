#!/usr/bin/env python
import sys
from setuptools import setup


setup(
    name='subscan',
    install_requires=['psycopg2-binary',
                      'argparse',
                      'requests',
                      'dnspython',
                      'tld',
                      'termcolor',
                     ],
    )
