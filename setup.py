from setuptools import setup
setup(
    name = "cronodump",
    version = "1.1.0",
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
    long_description_content_type='text/markdown',
    long_description = """
The cronodump utility can parse most of the databases created by the [CronosPro](https://www.cronos.ru/) database software
and dump it to several output formats.

The software is popular among Russian public offices, companies and police agencies.

Example usage:

    croconvert --csv <yourdbpath>

Will create a .csv dump of all records in your database.

or:

    crodump strudump <yourdbpath>

Will print details on the internal definitions of the tables present in your database.

For more details see the [README.md](https://github.com/alephdata/cronodump/blob/master/README.md) file.
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
