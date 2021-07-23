from readers import ByteReader
from TableDefinition import TableDefinition
from hexdump import ashex


class Field:
    def __init__(self, fielddef, data):
        self.decode(fielddef, data)

    def decode(self, fielddef, data):
        self.typ = fielddef.typ
        self.data = data

        # if typ is systemnumber, just convert to string for presentation
        if self.typ == 0:
            self.content = str(data)

        # decode internal file reference
        elif self.typ == 6:
            rd = ByteReader(data)
            self.flag = rd.readdword()
            self.remlen = rd.readdword()
            self.filename = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.extname = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.filedatarecord = rd.readtoseperator(b"\x1e").decode("cp1251")
            self.content = " ".join([self.filename, self.extname, self.filedatarecord])

        # currently assuming everything else to be strings, which is wrong
        else:
            self.content = data.decode("cp1251")


class Record:
    def __init__(self, sysnumber, tabledef, data):
        self.decode(sysnumber, tabledef, data)

    def decode(self, sysnumber, tabledef, data):
        """
        decode the fields in a record
        """
        self.data = data
        self.sysnumber = sysnumber
        self.table = tabledef

        self.fields = [Field(tabledef[0], sysnumber)]
        rd = ByteReader(data)
        for fielddef in tabledef[1:]:
            # read complex record indicated by b"\x1b"
            if rd.testbyte(27):
                rd.readbyte()
                size = rd.readdword()
                fielddata = rd.readbytes(size)
            else:
                fielddata = rd.readtoseperator(b"\x1e")

            self.fields.append(Field(fielddef, fielddata))
