#!/usr/bin/env python

from setuptools import setup, find_packages
import sys

if not sys.version_info[0] == 2:
    sys.exit("Sorry, Python 3 is not supported (yet)")

packages = find_packages()

setup(name='odlproxy',
      author='Assembly Data System',
      author_email="claudio.navisse@assembly.it",
      version='0.1',
      description='odlproxy',
      url='http://github.com/storborg/funniest',
      #packages=['odlproxy'],
      packages=packages,
      install_requires=['python-odlclient==0.0.1.dev13','bottle==0.12.13','openstacksdk==0.9.16','pika==0.10.0','futures==3.1.1'],
      #install_requires=['python-odlclient==0.0.1.dev13','CherryProxy==0.12''python-novaclient==9.0.1',],
      #dependency_links = ['https://bitbucket.org/decalage/cherryproxy/downloads/CherryProxy-0.12.zip'],
      scripts=['bin/odlproxy'],
      zip_safe=False)

