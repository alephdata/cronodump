from setuptools import setup
setup(
    name = "cronodump",
    version = "1.0.0",
    entry_points = {
        'console_scripts': [
            'croconvert=crodump.croconvert:main',
            'crodump=crodump.crodump:main',
        ],
    },
    packages = ['crodump'],
    author = "Willem Hengeveld, Dirk Engling",
    author_email = "itsme@xs4all.nl, erdgeist@erdgeist.org",
    description = "Tool and library for extracting data from Cronos databases.",
    long_description = """
Commandline tool which can convert Cronos 'DataBank' Bases to .csv format.
""",
    license = "MIT",
    keywords = "cronos dataconversion databaseexport",
    url = "https://github.com/alephdata/cronodump/",
    classifiers = [
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Topic :: Utilities',
        'Topic :: Database',
    ],
    python_requires = '>=3.7',
    extras_require={ 'templates': ['Jinja2'] },
)
