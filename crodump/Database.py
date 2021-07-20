import os
import re
from binascii import b2a_hex
from readers import ByteReader
from hexdump import strescape, toout
from TableDefinition import TableDefinition
from Datafile import Datafile


class Database:
    """represent the entire database, consisting of Stru, Index and Bank files"""

    def __init__(self, dbdir):
        self.dbdir = dbdir

        self.stru = self.getfile("Stru")
        self.index = self.getfile("Index")
        self.bank = self.getfile("Bank")
        self.sys = self.getfile("Sys")
        # BankTemp, Int

    def nrofrecords(self):
        return len(self.bank.tadidx)

    def getfile(self, name):
        try:
            datname = self.getname(name, "dat")
            tadname = self.getname(name, "tad")
            if datname and tadname:
                return Datafile(name, open(datname, "rb"), open(tadname, "rb"))
        except IOError:
            return

    def getname(self, name, ext):
        """
        get a case-insensitive filename match for 'name.ext'.
        Returns None when no matching file was not found.
        """
        basename = "Cro%s.%s" % (name, ext)
        for fn in os.scandir(self.dbdir):
            if basename.lower() == fn.name.lower():
                return os.path.join(self.dbdir, fn.name)

    def dump(self, args):
        if self.stru:
            self.stru.dump(args)
        if self.index:
            self.index.dump(args)
        if self.bank:
            self.bank.dump(args)
        if self.sys:
            self.sys.dump(args)

    def strudump(self, args):
        if not self.stru:
            print("missing CroStru file")
            return
        self.dump_db_table_defs(args)

    def decode_db_definition(self, data):
        """
        decode the 'bank' / database definition
        """
        rd = ByteReader(data)

        d = dict()
        while not rd.eof():
            keyname = rd.readname()
            if keyname in d:
                print("WARN: duplicate key: %s" % keyname)

            index_or_length = rd.readdword()
            if index_or_length >> 31:
                d[keyname] = rd.readbytes(index_or_length & 0x7FFFFFFF)
            else:
                refdata = self.stru.readrec(index_or_length)
                if refdata[:1] != b"\x04":
                    print("WARN: expected refdata to start with 0x04")
                d[keyname] = refdata[1:]
        return d

    def dump_db_definition(self, args, dbdict):
        """
        decode the 'bank' / database definition
        """
        for k, v in dbdict.items():
            if re.search(b"[^\x0d\x0a\x09\x20-\x7e\xc0-\xff]", v):
                print("%-20s - %s" % (k, toout(args, v)))
            else:
                print('%-20s - "%s"' % (k, strescape(v)))

    def dump_db_table_defs(self, args):
        """
        decode the table defs from recid #1, which always has table-id #3
        Note that I don't know if it is better to refer to this by recid, or by table-id.

        other table-id's found in CroStru:
            #4  -> large values referenced from tableid#3
        """
        dbinfo = self.stru.readrec(1)
        if dbinfo[:1] != b"\x03":
            print("WARN: expected dbinfo to start with 0x03")
        dbdef = self.decode_db_definition(dbinfo[1:])
        self.dump_db_definition(args, dbdef)

        for k, v in dbdef.items():
            if k.startswith("Base") and k[4:].isnumeric():
                print("== %s ==" % k)
                tbdef = TableDefinition(v)
                tbdef.dump(args)

    def enumerate_tables(self, files):
        dbinfo = self.stru.readrec(1)
        if dbinfo[:1] != b"\x03":
            print("WARN: expected dbinfo to start with 0x03")
        dbdef = self.decode_db_definition(dbinfo[1:])

        for k, v in dbdef.items():
            if k.startswith("Base") and k[4:].isnumeric():
                if files and k[4:] == '000':
                    yield TableDefinition(v)
                if not files and k[4:] != '000':
                    yield TableDefinition(v)

    def enumerate_records(self, table):
        """
        usage:
        for tab in db.enumerate_tables():
            for rec in db.enumerate_records(tab):
                print(sqlformatter(tab, rec))
        """
        for i in range(self.nrofrecords()):
            data = self.bank.readrec(i + 1)
            if data and data[0] == table.tableid:
                yield i + 1, [
                    record.decode("cp1251") for record in data[1:].split(b"\x1e")
                ]

    def enumerate_files(self, table):
        """
        """
        for i in range(self.nrofrecords()):
            data = self.bank.readrec(i + 1)
            if data and data[0] == table.tableid:
                yield i + 1, data[1:]

    def recdump(self, args):
        if args.index:
            dbfile = self.index
        elif args.sys:
            dbfile = self.sys
        elif args.stru:
            dbfile = self.stru
        else:
            dbfile = self.bank

        if not dbfile:
            print(".dat not found")
            return
        if args.skipencrypted and dbfile.encoding == 3:
            print("Skipping encrypted CroBank")
            return
        nerr = 0
        nr_recnone = 0
        nr_recempty = 0
        tabidxref = [0] * 256
        bytexref = [0] * 256
        for i in range(1, args.maxrecs + 1):
            try:
                data = dbfile.readrec(i)
                if args.find1d:
                    if data and (data.find(b"\x1d") > 0 or data.find(b"\x1b") > 0):
                        print("%d -> %s" % (i, b2a_hex(data)))
                        break

                elif not args.stats:
                    if data is None:
                        print("%5d: <deleted>" % i)
                    else:
                        print("%5d: %s" % (i, toout(args, data)))
                else:
                    if data is None:
                        nr_recnone += 1
                    elif not len(data):
                        nr_recempty += 1
                    else:
                        tabidxref[data[0]] += 1
                        for b in data[1:]:
                            bytexref[b] += 1
                nerr = 0
            except IndexError:
                break
            except Exception as e:
                print("%5d: <%s>" % (i, e))
                if args.debug:
                    raise
                nerr += 1
                if nerr > 5:
                    break
        if args.stats:
            print(
                "-- table-id stats --, %d * none, %d * empty"
                % (nr_recnone, nr_recempty)
            )
            for k, v in enumerate(tabidxref):
                if v:
                    print("%5d * %02x" % (v, k))
            print("-- byte stats --")
            for k, v in enumerate(bytexref):
                if v:
                    print("%5d * %02x" % (v, k))
