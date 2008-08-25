from setuptools import setup, find_packages
import os

version = '1.0'

setup(name='repoze.whoplugins.openid',
      version=version,
      description="An OpenID plugin for repoze.who",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
      keywords='openid repoze who identification authentication plugin',
      author='Christian Scholz',
      author_email='cs@comlounge.net',
      url='',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['repoze', 'repoze.whoplugins'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          # -*- Extra requirements: -*-
	  'python-openid>=2.0'
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
