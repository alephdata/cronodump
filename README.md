# cronodump

The cronodump utility can parse most of the databases created by the [CronosPro](https://www.cronos.ru/) database software
and dump it to several output formats.

The software is popular among Russian public offices, companies and police agenies.

# License

cronodump is released under the [MIT license](LICENSE).

# References

cronodump builds upon [documentation of the file format found in older versions of Cronos](http://sergsv.narod.ru/cronos.htm) and
the [subsequent implementation of a parser for the old file format](https://github.com/occrp/cronosparser) but dropped the heuristic
approach to guess offsets and obfuscation parameters for a more rigid parser. Refer to [todo the docs](docs/format.md) for further
details.
