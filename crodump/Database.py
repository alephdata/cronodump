from __future__ import print_function, division
import os
import re
from sys import stderr
from binascii import b2a_hex
from .readers import ByteReader
from .hexdump import strescape, toout, ashex
from .Datamodel import TableDefinition, Record
from .Datafile import Datafile
import base64
import struct
import crodump.koddecoder

import sys
if sys.version_info[0] == 2:
    sys.exit("cronodump needs python3")


class Database:
    """represent the entire database, consisting of Stru, Index and Bank files"""

    def __init__(self, dbdir, kod=crodump.koddecoder.new()):
        """
        `dbdir` is the directory containing the Cro*.dat and Cro*.tad files.
        `kod` is optionally a KOD coder object.
              by default the v3 KOD coding will be used.
        """
        self.dbdir = dbdir
        self.kod = kod

        # Stru+Index+Bank for the components for most databases
        self.stru = self.getfile("Stru")
        self.index = self.getfile("Index")
        self.bank = self.getfile("Bank")

        # the Sys file resides in the "Program Files\Cronos" directory, and
        # contains an index of all known databases.
        self.sys = self.getfile("Sys")

    def nrofrecords(self):
        return len(self.bank.tadidx)

    def getfile(self, name):
        """
        Returns a Datafile object for `name`.
        this function expects a `Cro<name>.dat` and a `Cro<name>.tad` file.
        When no such files exist, or only one, then None is returned.

        `name` is matched case insensitively
        """
        try:
            datname = self.getname(name, "dat")
            tadname = self.getname(name, "tad")
            if datname and tadname:
                return Datafile(name, open(datname, "rb"), open(tadname, "rb"), self.kod)
        except IOError:
            return

    def getname(self, name, ext):
        """
        Get a case-insensitive filename match for 'name.ext'.
        Returns None when no matching file was not found.
        """
        basename = "Cro%s.%s" % (name, ext)
        for fn in os.listdir(self.dbdir):
            if basename.lower() == fn.lower():
                return os.path.join(self.dbdir, fn)

    def dump(self, args):
        """
        Calls the `dump` method on all database components.
        """
        if self.stru:
            self.stru.dump(args)
        if self.index:
            self.index.dump(args)
        if self.bank:
            self.bank.dump(args)
        if self.sys:
            self.sys.dump(args)

    def strudump(self, args):
        """
        prints all info found in the CroStru file.
        """
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
                tbdef = TableDefinition(v, dbdef.get("BaseImage" + k[4:], b''))
                tbdef.dump(args)
            elif k == "NS1":
                self.dump_ns1(v)

    def dump_ns1(self, data):
        if len(data)<2:
            print("NS1 is unexpectedly short")
            return
        unk1, sh, = struct.unpack_from("<BB", data, 0)

        # NS1 is encoded with the default KOD table,
        # so we are not using stru.kod here.
        ns1kod = crodump.koddecoder.new()
        decoded_data = ns1kod.decode(sh, data[2:])

        if len(decoded_data) < 12:
            print("NS1 is unexpectedly short")
            return
        serial, unk2, pwlen, = struct.unpack_from("<LLL", decoded_data, 0)
        password = decoded_data[12:12+pwlen].decode('cp1251')

        print("== NS1: (%02x,%02x) -> %6d, %d, %d:'%s'" % (unk1, sh, serial, unk2, pwlen, password))

    def enumerate_tables(self, files=False):
        """
        yields a TableDefinition object for all `BaseNNN` entries found in CroStru
        """
        dbinfo = self.stru.readrec(1)
        if dbinfo[:1] != b"\x03":
            print("WARN: expected dbinfo to start with 0x03")
        try:
            dbdef = self.decode_db_definition(dbinfo[1:])
        except Exception as e:
            print("ERROR decoding db definition: %s" % e)
            print("This could possibly mean that you need to try with the --strucrack option")
            return

        for k, v in dbdef.items():
            if k.startswith("Base") and k[4:].isnumeric():
                if files and k[4:] == "000":
                    yield TableDefinition(v)
                if not files and k[4:] != "000":
                    yield TableDefinition(v, dbdef.get("BaseImage" + k[4:], b''))

    def enumerate_records(self, table):
        """
        Yields a Record object for all records in CroBank matching
        the tableid from `table`

        usage:
        for tab in db.enumerate_tables():
            for rec in db.enumerate_records(tab):
                print(sqlformatter(tab, rec))
        """
        for i in range(self.nrofrecords()):
            data = self.bank.readrec(i + 1)
            if data and data[0] == table.tableid:
                try:
                    yield Record(i + 1, table.fields, data[1:])
                except EOFError:
                    print("Record %d too short: -- %s" % (i+1, ashex(data)), file=stderr)
                except Exception as e:
                    print("Record %d broken: ERROR '%s' -- %s" % (i+1, e, ashex(data)), file=stderr)

    def enumerate_files(self, table):
        """
        Yield all file contents found in CroBank for `table`.
        This is most likely the table with id 0.
        """
        for i in range(self.nrofrecords()):
            data = self.bank.readrec(i + 1)
            if data and data[0] == table.tableid:
                yield i + 1, data[1:]

    def get_record(self, index, asbase64=False):
        """
        Retrieve a single record from CroBank with record number `index`.
        """
        data = self.bank.readrec(int(index))
        if asbase64:
            return base64.b64encode(data[1:]).decode('utf-8')
        else:
            return data[1:]

    def recdump(self, args):
        """
        Function for outputing record contents of the various .dat files.

        This function is mostly useful for reverse-engineering the database format.
        """
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
                        print("record with '1d': %d -> %s" % (i, b2a_hex(data)))
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
            print("-- table-id stats --, %d * none, %d * empty" % (nr_recnone, nr_recempty))
            for k, v in enumerate(tabidxref):
                if v:
                    print("%5d * %02x" % (v, k))
            print("-- byte stats --")
            for k, v in enumerate(bytexref):
                if v:
                    print("%5d * %02x" % (v, k))
