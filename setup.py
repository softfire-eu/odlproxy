__author__ = 'Massimiliano Romano'

from setuptools import setup

import sys
if not sys.version_info[0] == 2:
    sys.exit("Sorry, Python 3 is not supported (yet)")

setup(name='odlproxy',
      version='0.1',
      description='odlproxy',
      url='http://github.com/storborg/funniest',
      author='Assembly Data System',
      packages=['odlproxy'],
      install_requires=['python-odlclient==0.0.1.dev13','bottle==0.12.13','openstacksdk==0.9.16'],
      #install_requires=['python-odlclient==0.0.1.dev13','CherryProxy==0.12'],
      #dependency_links = ['https://bitbucket.org/decalage/cherryproxy/downloads/CherryProxy-0.12.zip'],
      scripts=['bin/odlproxy'],
      zip_safe=False)

# CherryProxy cannot be downloaded with:
#
#   pip install CherryProxy because pip cannot find the download url from pypi website
#
# you need to manual install the package with the following command:
#
#   pip install https://bitbucket.org/decalage/cherryproxy/downloads/CherryProxy-0.12.zip -vvvv
#
#
