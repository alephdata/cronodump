from readers import ByteReader
from hexdump import ashex


class Field:
    """
    Contains a single fully decoded value.
    """
    def __init__(self, fielddef, data):
        self.decode(fielddef, data)

    def decode(self, fielddef, data):
        self.typ = fielddef.typ
        self.data = data

        if self.typ == 0:
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

        elif self.typ == 9:
            # just hexdump foreign keys
            self.content = ashex(data)

        else:
            # currently assuming everything else to be strings, which is wrong
            self.content = data.decode("cp1251", 'ignore')


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
