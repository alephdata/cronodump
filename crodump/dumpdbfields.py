"""
`dumpdbfields` demonstrates how to enumerate tables and records.
"""
import os
import os.path
from .Database import Database
from .crodump import strucrack, dbcrack
from .hexdump import unhex


def processargs(args):
    for dbpath in args.dbdirs:
        if args.recurse:
            for path, _, files in os.walk(dbpath):
                # check if there is a crostru file in this directory.
                if any(_ for _ in files if _.lower() == "crostru.dat"):
                    yield path
        else:
            yield dbpath


def main():
    import argparse

    parser = argparse.ArgumentParser(description="db field dumper")
    parser.add_argument("--kod", type=str, help="specify custom KOD table")
    parser.add_argument("--strucrack", action="store_true", help="infer the KOD sbox from CroStru.dat")
    parser.add_argument("--dbcrack", action="store_true", help="infer the KOD sbox from CroIndex.dat+CroBank.dat")
    parser.add_argument("--nokod", "-n", action="store_true", help="don't KOD decode")
    parser.add_argument("--maxrecs", "-m", type=int, default=100)
    parser.add_argument("--recurse", "-r", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("dbdirs", type=str, nargs='*')
    args = parser.parse_args()

    for path in processargs(args):
        try:
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
                cargs.dbdir = path
                cargs.sys = False
                cargs.silent = True
                cracked = strucrack(None, cargs)
                if not cracked:
                    return
                kod = crodump.koddecoder.new(cracked)
            elif args.dbcrack:
                class Cls: pass
                cargs = Cls()
                cargs.dbdir = path
                cargs.sys = False
                cargs.silent = True
                cracked = dbcrack(None, cargs)
                if not cracked:
                    return
                kod = crodump.koddecoder.new(cracked)
            else:
                kod = crodump.koddecoder.new()

            db = Database(path, kod)
            for tab in db.enumerate_tables():
                tab.dump(args)
                print("nr of records: %d" % db.nrofrecords())
                i = 0
                for rec in db.enumerate_records(tab):
                    for field, fielddef in zip(rec.fields, tab.fields):
                        print(">> %s -- %s" % (fielddef, field.content))
                    i += 1
                    if i > args.maxrecs:
                        break
        except Exception as e:
            print("ERROR: %s" % e)


if __name__ == "__main__":
    main()
