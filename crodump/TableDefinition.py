import struct
from hexdump import hexdump, asasc, tohex, unhex, strescape, toout
from readers import ByteReader


class FieldDefinition:
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
                self.typ,
                self.idx1,
                self.idx2,
                self.flags,
                self.minval,
                self.maxval,
                self.unk4,
                "'%s'" % self.name,
                tohex(self.remaining),
            )
        else:
            return "Type: %2d %2d    %d,%d       - '%s'" % (
                self.typ,
                self.idx1,
                self.flags,
                self.minval,
                self.name,
            )


class TableDefinition:
    def __init__(self, data):
        self.decode(data)

    def decode(self, data):
        """
        decode the 'base' / table definition
        """
        rd = ByteReader(data)

        self.unk1 = rd.readword()
        self.version = rd.readbyte()
        if self.version > 1:
            _ = rd.readbyte()  # always 0 anyway

        self.unk2 = (
            rd.readbyte()
        )  # if this is not 5 (but 9), there's another 4 bytes inserted, this could be a length-byte.
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
            l = rd.readword()
            fielddef = rd.readbytes(l)
            self.fields.append(FieldDefinition(fielddef))

        # Between the first and the second block, there's some byte strings inbetween, count
        # given in first dword
        self.extraunkblocks = rd.readdword()

        for _ in range(self.extraunkblocks):
            l = rd.readword()
            skip = rd.readbytes(l)

        try:
            # Then there's another unknow dword and then (probably section indicator) 02 byte
            self.unk8_ = rd.readdword()
            if rd.readbyte() != 2:
                print( "Warning: FieldDefinition Section 2 not marked with a 2")
            self.unk9 = rd.readdword()

            # Then there's the amount of extra fields in the second section
            extrafields = rd.readdword()

            for _ in range(extrafields):
                l = rd.readword()
                fielddef = rd.readbytes(l)
                self.fields.append(FieldDefinition(fielddef))
        except:
            pass

        try:
            self.terminator = rd.readdword()
        except:
            print("Warning: FieldDefinition section not terminated")

        self.fields.sort(key=lambda field: field.idx2)

        self.remainingdata = rd.readbytes()

    def __str__(self):
        return "%d,%d<%d,%d,%d>%d  %d,%d '%s'  '%s'" % (
            self.unk1,
            self.version,
            self.unk2,
            self.unk3,
            self.unk4,
            self.tableid,
            self.unk7,
            len(self.fields),
            self.tablename,
            self.abbrev,
        )

    def dump(self, args):
        if args.verbose:
            print("table: %s" % tohex(self.headerdata))

        print(str(self))

        for offset, field in enumerate(self.fields):
            if args.verbose:
                print(
                    "field: @%4d: %04x - %s"
                    % (offset, len(field.defdata), tohex(field.defdata))
                )
            print(str(field))
        if args.verbose:
            print("remaining: %s" % tohex(self.remainingdata))
