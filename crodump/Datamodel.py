# -*- coding: utf-8 -*-
from .hexdump import tohex, ashex
from .readers import ByteReader


class FieldDefinition:
    """
    Contains the properties for a single field in a record.
    """
    def __init__(self, data):
        self.decode(data)

    def decode(self, data):
        self.defdata = data

        rd = ByteReader(data)
        self.typ = rd.readword()
        self.idx1 = rd.readdword()
        self.name = rd.readname()
        self.flags = rd.readdword()
        self.minval = rd.readbyte()  # Always 1
        if self.typ:
            self.idx2 = rd.readdword()
            self.maxval = rd.readdword()  # max value or length
            self.unk4 = rd.readdword()  # Always 0x00000009 or 0x0001000d
        else:
            self.idx2 = 0
            self.maxval = self.unk4 = None
        self.remaining = rd.readbytes()

    def __str__(self):
        if self.typ:
            return "Type: %2d (%2d/%2d) %04x,(%d-%4d),%04x - %-40s -- %s" % (
                    self.typ, self.idx1, self.idx2,
                    self.flags, self.minval, self.maxval, self.unk4,
                    "'%s'" % self.name, tohex(self.remaining))
        else:
            return "Type: %2d %2d    %d,%d       - '%s'" % (
                    self.typ, self.idx1, self.flags, self.minval, self.name)

    def sqltype(self):
        return { 0: "INTEGER PRIMARY KEY",
                 1: "INTEGER",
                 2: "VARCHAR(" + str(self.maxval) + ")",
                 3: "TEXT",          # dictionaray
                 4: "DATE",
                 5: "TIMESTAMP",
                 6: "TEXT",          # file reference
        }.get(self.typ, "TEXT")


class TableImage:
    def __init__(self, data):
        self.decode(data)

    def decode(self, data):
        if not len(data):
            self.filename = "none"
            self.data = b''
            return

        rd = ByteReader(data)

        _ = rd.readbyte()
        namelen = rd.readdword()
        self.filename = rd.readbytes(namelen).decode("cp1251", 'ignore')

        imagelen = rd.readdword()
        self.data = rd.readbytes(imagelen)


class TableDefinition:
    def __init__(self, data, image=''):
        self.decode(data, image)

    def decode(self, data, image):
        """
        decode the 'base' / table definition
        """
        rd = ByteReader(data)

        self.unk1 = rd.readword()
        self.version = rd.readbyte()
        if self.version > 1:
            _ = rd.readbyte()  # always 0 anyway

        # if this is not 5 (but 9), there's another 4 bytes inserted, this could be a length-byte.
        self.unk2 = rd.readbyte()

        self.unk3 = rd.readbyte()
        if self.unk2 > 5:  # seen only 5 and 9 for now with 9 implying an extra dword
            _ = rd.readdword()
        self.unk4 = rd.readdword()

        self.tableid = rd.readdword()

        self.tablename = rd.readname()
        self.abbrev = rd.readname()
        self.unk7 = rd.readdword()
        nrfields = rd.readdword()

        self.headerdata = data[: rd.o]

        # There's (at least) two blocks describing fields, ended when encountering ffffffff
        self.fields = []
        for _ in range(nrfields):
            deflen = rd.readword()
            fielddef = rd.readbytes(deflen)
            self.fields.append(FieldDefinition(fielddef))

        # Between the first and the second block, there's some byte strings inbetween, count
        # given in first dword
        self.extraunkdatastrings = rd.readdword()

        for _ in range(self.extraunkdatastrings):
            datalen = rd.readword()
            skip = rd.readbytes(datalen)

        try:
            # Then there's another unknow dword and then (probably section indicator) 02 byte
            self.unk8_ = rd.readdword()
            if rd.readbyte() != 2:
                print("Warning: FieldDefinition Section 2 not marked with a 2")
            self.unk9 = rd.readdword()

            # Then there's the amount of extra fields in the second section
            nrextrafields = rd.readdword()

            for _ in range(nrextrafields):
                deflen = rd.readword()
                fielddef = rd.readbytes(deflen)
                self.fields.append(FieldDefinition(fielddef))
        except Exception as e:
            print("Warning: Error '%s' parsing FieldDefinitions" % e)

        try:
            self.terminator = rd.readdword()
        except EOFError:
            print("Warning: FieldDefinition section not terminated")
        except Exception as e:
            print("Warning: Error '%s' parsing Tabledefinition" % e)

        self.fields.sort(key=lambda field: field.idx2)

        self.remainingdata = rd.readbytes()

        self.tableimage = TableImage(image)

    def __str__(self):
        return "%d,%d<%d,%d,%d>%d  %d,%d '%s'  '%s'  [TableImage(%d bytes): %s]" % (
                self.unk1, self.version, self.unk2, self.unk3, self.unk4, self.tableid,
                self.unk7, len(self.fields),
                self.tablename, self.abbrev, len(self.tableimage.data), self.tableimage.filename)

    def dump(self, args):
        if args.verbose:
            print("table: %s" % tohex(self.headerdata))

        print(str(self))

        for i, field in enumerate(self.fields):
            if args.verbose:
                print("field#%2d: %04x - %s" % (
                    i, len(field.defdata), tohex(field.defdata)))
            print(str(field))
        if args.verbose:
            print("remaining: %s" % tohex(self.remainingdata))


class Field:
    """
    Contains a single fully decoded value.
    """
    def __init__(self, fielddef, data):
        self.decode(fielddef, data)

    def decode(self, fielddef, data):
        self.typ = fielddef.typ
        self.data = data

        if not data:
            self.content = ""
            return
        elif self.typ == 0:
            # typ 0 is the recno, or as cronos calls this: Системный номер, systemnumber.
            # just convert this to string for presentation
            self.content = str(data)

        elif self.typ == 6:
            # decode internal file reference
            rd = ByteReader(data)
            self.flag = rd.readdword()
            self.remlen = rd.readdword()
            self.filename = rd.readtoseperator(b"\x1e").decode("cp1251", 'ignore')
            self.extname = rd.readtoseperator(b"\x1e").decode("cp1251", 'ignore')
            self.filedatarecord = rd.readtoseperator(b"\x1e").decode("cp1251", 'ignore')
            self.content = " ".join([self.filename, self.extname, self.filedatarecord])

        elif self.typ == 7 or self.typ == 8 or self.typ == 9:
            # just hexdump foreign keys
            self.content = ashex(data)

        else:
            # currently assuming everything else to be strings, which is wrong
            self.content = data.rstrip(b"\x00").decode("cp1251", 'ignore')


class Record:
    """
    Contains a single fully decoded record.
    """
    def __init__(self, recno, tabledef, data):
        self.decode(recno, tabledef, data)

    def decode(self, recno, tabledef, data):
        """
        decode the fields in a record
        """
        self.data = data
        self.recno = recno
        self.table = tabledef

        # start with the record number, or as Cronos calls this:
        # the system number, in russian: Системный номер.
        self.fields = [ Field(tabledef[0], str(recno)) ]

        rd = ByteReader(data)
        for fielddef in tabledef[1:]:
            if not rd.eof() and rd.testbyte(0x1b):
                # read complex record indicated by b"\x1b"
                rd.readbyte()
                size = rd.readdword()
                fielddata = rd.readbytes(size)
            else:
                fielddata = rd.readtoseperator(b"\x1e")

            self.fields.append(Field(fielddef, fielddata))
