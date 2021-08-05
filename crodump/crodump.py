import io
from .koddecoder import decode_kod
from .hexdump import unhex
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


def kod_hexdump(args):
    """
    handle the `kodump` subcommand, KOD decode a section of a data file

    This function is mostly useful for reverse-engineering the database format.
    """
    args.offset = int(args.offset, 0)
    if args.length:
        args.length = int(args.length, 0)
    elif args.endofs:
        args.endofs = int(args.endofs, 0)
        args.length = args.endofs - args.offset

    if args.width:
        args.width = int(args.width, 0)
    else:
        args.width = 64 if args.ascdump else 16

    if args.filename:
        with open(args.filename, "rb") as fh:
            if args.length is None:
                fh.seek(0, io.SEEK_END)
                filesize = fh.tell()
                args.length = filesize - args.offset
            fh.seek(args.offset)
            data = fh.read(args.length)
            decode_kod(args, data)
    else:
        # no filename -> read from stdin.
        import sys

        data = sys.stdin.buffer.read()
        if args.unhex:
            data = unhex(data)
        decode_kod(args, data)


def cro_dump(args):
    """handle 'crodump' subcommand"""
    db = Database(args.dbdir)
    db.dump(args)


def stru_dump(args):
    """handle 'strudump' subcommand"""
    db = Database(args.dbdir)
    db.strudump(args)


def sys_dump(args):
    """hexdump all CroSys records"""
    db = Database(args.dbdir)
    if db.sys:
        db.sys.dump(args)


def rec_dump(args):
    """hexdump all records of the specified CroXXX.dat file."""
    if args.maxrecs:
        args.maxrecs = int(args.maxrecs, 0)
    else:
        # an arbitrarily large number.
        args.maxrecs = 0xFFFFFFFF

    db = Database(args.dbdir)
    db.recdump(args)


def destruct(args):
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

def main():
    import argparse

    parser = argparse.ArgumentParser(description="CRO hexdumper")
    subparsers = parser.add_subparsers(title='commands', help='Use the --help option for the individual sub commands for more details')
    parser.set_defaults(handler=lambda args:parser.print_help())
    parser.add_argument("--debug", action="store_true", help="break on exceptions")

    ko = subparsers.add_parser("kodump", help="KOD/hex dumper")
    ko.add_argument("--offset", "-o", type=str, default="0")
    ko.add_argument("--length", "-l", type=str)
    ko.add_argument("--width", "-w", type=str)
    ko.add_argument("--endofs", "-e", type=str)
    ko.add_argument("--unhex", "-x", action="store_true", help="assume the input contains hex data")
    ko.add_argument("--shift", "-s", type=str, help="KOD decode with the specified shift")
    ko.add_argument("--increment", "-i", action="store_true",
                    help="assume data is already KOD decoded, but with wrong shift -> dump alternatives.")
    ko.add_argument("--ascdump", "-a", action="store_true", help="CP1251 asc dump of the data")
    ko.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")
    ko.add_argument("filename", type=str, nargs="?", help="dump either stdin, or the specified file")
    ko.set_defaults(handler=kod_hexdump)

    p = subparsers.add_parser("crodump", help="CROdumper")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--koddecode", "-k", action="store_true")
    p.add_argument("--ascdump", "-a", action="store_true")
    p.add_argument("--nokod", "-n", action="store_true")
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
    p.add_argument("--maxrecs", "-n", type=str, help="max nr or recots to output")
    p.add_argument("--find1d", action="store_true")
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

    args = parser.parse_args()

    if args.handler:
        args.handler(args)


if __name__ == "__main__":
    main()
