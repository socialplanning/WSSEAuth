from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='WSSEAuth',
      version=version,
      description="WSSE authentication",
      long_description="""WSSE authentication wsgi middleware""",
      classifiers=[], # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='David Turner',
      author_email='novalis@openplans.org',
      url='',
      license='GPLv3 or any later version',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
