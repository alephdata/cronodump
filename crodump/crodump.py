from .kodump import kod_hexdump
from .hexdump import unhex, tohex
from .readers import ByteReader
from .Database import Database
from .Datamodel import TableDefinition


def destruct_sys3_def(rd):
    # todo
    pass


def destruct_sys4_def(rd):
    """
    decode type 4 of the records found in CroSys.

    This function is only useful for reverse-engineering the CroSys format.
    """
    n = rd.readdword()
    for _ in range(n):
        marker = rd.readdword()
        description = rd.readlongstring()
        path = rd.readlongstring()
        marker2 = rd.readdword()

        print("%08x;%08x: %-50s : %s" % (marker, marker2, path, description))


def destruct_sys_definition(args, data):
    """
    Decode the 'sys' / dbindex definition

    This function is only useful for reverse-engineering the CroSys format.
    """
    rd = ByteReader(data)

    systype = rd.readbyte()
    if systype == 3:
        return destruct_sys3_def(rd)
    elif systype == 4:
        return destruct_sys4_def(rd)
    else:
        raise Exception("unsupported sys record")


def cro_dump(kod, args):
    """handle 'crodump' subcommand"""
    if args.maxrecs:
        args.maxrecs = int(args.maxrecs, 0)
    else:
        # an arbitrarily large number.
        args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, kod)
    db.dump(args)


def stru_dump(kod, args):
    """handle 'strudump' subcommand"""
    db = Database(args.dbdir, kod)
    db.strudump(args)


def sys_dump(kod, args):
    """hexdump all CroSys records"""
    # an arbitrarily large number.
    args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, kod)
    if db.sys:
        db.sys.dump(args)


def rec_dump(kod, args):
    """hexdump all records of the specified CroXXX.dat file."""
    if args.maxrecs:
        args.maxrecs = int(args.maxrecs, 0)
    else:
        # an arbitrarily large number.
        args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir, kod)
    db.recdump(args)


def destruct(kod, args):
    """
    decode the index#1 structure information record
    Takes hex input from stdin.
    """
    import sys

    data = sys.stdin.buffer.read()
    data = unhex(data)

    if args.type == 1:
        # create a dummy db object
        db = Database(".")
        db.dump_db_definition(args, data)
    elif args.type == 2:
        tbdef = TableDefinition(data)
        tbdef.dump(args)
    elif args.type == 3:
        destruct_sys_definition(args, data)


def strucrack(kod, args):
    """
    This function derives the KOD key from the assumption that most bytes in
    the CroStru records will be zero, given a sufficient number of CroStru
    items, statistically the most common bytes will encode to '0x00'
    """

    # start without 'KOD' table, so we will get the encrypted records
    db = Database(args.dbdir, None)
    if args.sys:
        table = db.sys
        if not db.sys:
            print("no CroSys.dat file found in %s" % args.dbdir)
            return
    else:
        table = db.stru
        if not db.stru:
            print("no CroStru.dat file found in %s" % args.dbdir)
            return

    xref = [ [0]*256 for _ in range(256) ]
    for i, data in enumerate(table.enumrecords()):
        if not data: continue
        for ofs, byte in enumerate(data):
            xref[(ofs+i+1)%256][byte] += 1

    KOD = [0] * 256
    for i, xx in enumerate(xref):
        k, v = max(enumerate(xx), key=lambda kv: kv[1])
        KOD[k] = i

    if not args.silent:
        print(tohex(bytes(KOD)))

    return KOD

def dbcrack(kod, args):
    """
    This function derives the KOD key from the assumption that most records in CroIndex
    and CroBank will be compressed, and start with:
      uint16 size
      byte  0x08
      byte  0x00

    So because the fourth byte in each record will be 0x00 when kod-decoded, I can
    use this as the inverse of the KOD table, adjusting for record-index.

    """
    # start without 'KOD' table, so we will get the encrypted records
    db = Database(args.dbdir, None)
    xref = [ [0]*256 for _ in range(256) ]

    for dbfile in db.bank, db.index:
        if not dbfile:
            print("no data file found in %s" % args.dbdir)
            return
        for i in range(1, min(10000, dbfile.nrofrecords())):
            rec = dbfile.readrec(i)
            if rec and len(rec)>11:
                xref[(i+3)%256][rec[3]] += 1

    KOD = [0] * 256
    for i, xx in enumerate(xref):
        k, v = max(enumerate(xx), key=lambda kv: kv[1])
        KOD[k] = i

    if not args.silent:
        print(tohex(bytes(KOD)))

    return KOD


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CRO hexdumper")
    subparsers = parser.add_subparsers(title='commands',
                        help='Use the --help option for the individual sub commands for more details')
    parser.set_defaults(handler=lambda *args: parser.print_help())
    parser.add_argument("--debug", action="store_true", help="break on exceptions")
    parser.add_argument("--kod", type=str, help="specify custom KOD table")
    parser.add_argument("--strucrack", action="store_true", help="infer the KOD sbox from CroStru.dat")
    parser.add_argument("--dbcrack", action="store_true", help="infer the KOD sbox from CroBank.dat + CroIndex.dat")
    parser.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")

    p = subparsers.add_parser("kodump", help="KOD/hex dumper")
    p.add_argument("--offset", "-o", type=str, default="0")
    p.add_argument("--length", "-l", type=str)
    p.add_argument("--width", "-w", type=str)
    p.add_argument("--endofs", "-e", type=str)
    p.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")
    p.add_argument("--unhex", "-x", action="store_true", help="assume the input contains hex data")
    p.add_argument("--shift", "-s", type=str, help="KOD decode with the specified shift")
    p.add_argument("--increment", "-i", action="store_true",
                   help="assume data is already KOD decoded, but with wrong shift -> dump alternatives.")
    p.add_argument("--ascdump", "-a", action="store_true", help="CP1251 asc dump of the data")
    p.add_argument("--invkod", "-I", action="store_true", help="KOD encode")
    p.add_argument("filename", type=str, nargs="?", help="dump either stdin, or the specified file")
    p.set_defaults(handler=kod_hexdump)

    p = subparsers.add_parser("crodump", help="CROdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--maxrecs", "-m", type=str, help="max nr or recots to output")
    p.add_argument("--nodecompress", action="store_false", dest="decompress", default="true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=cro_dump)

    p = subparsers.add_parser("sysdump", help="SYSdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--nodecompress", action="store_false", dest="decompress", default="true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=sys_dump)

    p = subparsers.add_parser("recdump", help="record dumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--maxrecs", "-m", type=str, help="max nr or recots to output")
    p.add_argument("--find1d", action="store_true", help="Find records with 0x1d in it")
    p.add_argument("--stats", action="store_true", help="calc table stats from the first byte of each record",)
    p.add_argument("--index", action="store_true", help="dump CroIndex")
    p.add_argument("--stru", action="store_true", help="dump CroIndex")
    p.add_argument("--bank", action="store_true", help="dump CroBank")
    p.add_argument("--sys", action="store_true", help="dump CroSys")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=rec_dump)

    p = subparsers.add_parser("strudump", help="STRUdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=stru_dump)

    p = subparsers.add_parser("destruct", help="Stru dumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--type", "-t", type=int, help="what type of record to destruct")
    p.set_defaults(handler=destruct)

    p = subparsers.add_parser("strucrack", help="Crack v4 KOD encrypion, bypassing the need for the database password.")
    p.add_argument("--sys", action="store_true", help="Use CroSys for cracking")
    p.add_argument("--silent", action="store_true", help="no output")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=strucrack)

    p = subparsers.add_parser("dbcrack", help="Crack v4 KOD encrypion, bypassing the need for the database password.")
    p.add_argument("--silent", action="store_true", help="no output")
    p.add_argument("dbdir", type=str)
    p.set_defaults(handler=dbcrack)

    args = parser.parse_args()

    import crodump.koddecoder
    if args.kod:
        if len(args.kod)!=512:
            raise Exception("--kod should have a 512 hex digit argument")
        kod = crodump.koddecoder.new(list(unhex(args.kod)))
    elif args.nokod:
        kod = None
    elif args.strucrack:
        class Cls: pass
        cargs = Cls()
        cargs.dbdir = args.dbdir
        cargs.sys = False
        cargs.silent = True
        cracked = strucrack(None, cargs)
        if not cracked:
            return
        kod = crodump.koddecoder.new(cracked)
    elif args.dbcrack:
        class Cls: pass
        cargs = Cls()
        cargs.dbdir = args.dbdir
        cargs.sys = False
        cargs.silent = True
        cracked = dbcrack(None, cargs)
        if not cracked:
            return
        kod = crodump.koddecoder.new(cracked)
    else:
        kod = crodump.koddecoder.new()

    if args.handler:
        args.handler(kod, args)


if __name__ == "__main__":
    main()
