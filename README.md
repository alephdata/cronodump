# cronodump

The cronodump utility can parse most of the databases created by the [CronosPro](https://www.cronos.ru/) database software
and dump it to several output formats.

The software is popular among Russian public offices, companies and police agencies.


# Quick start

In its simplest form, without any dependencies, the croconvert command creates a [CSV](https://en.wikipedia.org/wiki/Comma-separated_values) representation of all the database's tables and a copy of all files contained in the database:

```bash
bin/croconvert --csv test_data/all_field_types
```

By default it creates a `cronodump-YYYY-mm-DD-HH-MM-SS-ffffff/` directory containing CSV files for each table found. It will under this directory also create a `Files-FL/` directory containing all the files stored in the Database, regardless if they are (still) referenced in any data table. All files that are actually referenced (and thus are known by their filename) will be stored under the `Files-Referenced` directory. With the `--outputdir` option you can chose your own dump location.


# Templates

The croconvert command can use the powerful [jinja templating framework](https://jinja.palletsprojects.com/en/3.0.x/) to render more file formats like PostgreSQL and HTML.
The default action for `croconvert` is to convert the database using the `html` template.
Use

```bash
python3 -m venv ./venc
. venv/bin/activate
pip install jinja2
bin/croconvert test_data/all_field_types > test_data.html
```

to dump an HTML file with all tables found in the database, files listed and ready for download as inlined [data URI](https://en.wikipedia.org/wiki/Data_URI_scheme) and all table images inlined as well. Note that the resulting HTML file can be huge for large databases, causing a lot of load on browsers when trying to open them.


The `-t postgres` command will dump the table schemes and records as valid `CREATE TABLE` and `INSERT INTO` statements to stdout. This dump can then be imported in a PostgreSQL database. Note that the backslash character is not escaped and thus the [`standard_conforming_strings`](https://www.postgresql.org/docs/current/runtime-config-compatible.html#GUC-STANDARD-CONFORMING-STRINGS) option should be off.

Pull requests for [more templates supporting other output types](/templates) are welcome.


# Inspection

There's a `bin/crodump` tool to further investigate databases. This might be useful for extracting metadata like path names of table image files or input and output forms. Not all metadata has yet been completely reverse engineered, so some experience with understanding binary dumps might be required.

The crodump script has a plethora of options but in the most basic for the `strudump` sub command will provide a rich variety of metadata to look further:

```bash
bin/crodump strudump -v -a test_data/all_field_types/
```
The `-a` option tells strudump to output ascii instead of a hexdump.

For a low level dump of the database contents, use:
```bash
bin/crodump crodump -v  test_data/all_field_types/
```
The `-v` option tells crodump to include all unused byte ranges, this may be useful when identifying deleted records.

For a bit higher level dump of the database contents, use:
```bash
bin/crodump recdump  test_data/all_field_types/
```
This will print a hexdump of all records for all tables.


# Installing

`cronodump` requires python 3.7 or later. It has been tested on Linux, MacOS and Windows.
There is one optional requirement: the `Jinja2` templating engine, but it will install fine without.

There are several ways of installing `cronodump`:

 * You can run `cronodump` directly from the cloned git repository, by using the shell scripts in the `bin` subdirectory.
 * You can install `cronodump` in your python environment by ruinning: `python setup.py  build install`.
 * You can install `cronodump` from the public [pypi repository](https://pypi.org/project/cronodump/) with `pip install cronodump`.
 * You can install `cronodump` with the `Jinja2` templating engine from the public [pypi repository](https://pypi.org/project/cronodump/) with `pip install cronodump[templates]`.


# Terminology

We decided to use the more common terminology for database, tables, records, etc.
Here is a table showing how cronos calls these:

| what | cronos english | cronos russian
|:------ |:------ |:------ 
| Database  |  Bank   | Банк 
| Table     |  Base   | Базы
| Record    |  Record | Записи
| Field     |  Field  | поля
| recid     |  System Number | Системный номер


# License

cronodump is released under the [MIT license](LICENSE).


# References

cronodump builds upon [documentation of the file format found in older versions of Cronos](http://sergsv.narod.ru/cronos.htm) and
the [subsequent implementation of a parser for the old file format](https://github.com/occrp/cronosparser) but dropped the heuristic
approach to guess offsets and obfuscation parameters for a more rigid parser. Refer to [the docs](docs/cronos-research.md) for further
details.
