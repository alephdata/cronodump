"""
`dumpdbfields` demonstrates how to enumerate tables and records.
"""
import os
import os.path
from .Database import Database


def main():
    import sys
    if len(sys.argv) == 1:
        print("Usage: python3 dumpdbfields.py <path> [reclimit:100]")
        print("""
For each Cronos database found under <path>, will output the first `reclimit`
records of each table found in those databases""")
        return
    dbpath = sys.argv[1]
    reclimit = int(sys.argv[2], 0) if len(sys.argv)==3 else 100

    # construct a dummy args object.
    class Cls: pass
    args = Cls()
    args.verbose = False

    # recurse all subdirectories
    for path, _, files in os.walk(dbpath):

        # check if there is a crostru file in this directory.
        if any(_ for _ in files if _.lower() == "crostru.dat"):
            print("==>", path, "<==")

            try:
                db = Database(path)
                for tab in db.enumerate_tables():
                    tab.dump(args)
                    print("nr of records: %d" % db.nrofrecords())
                    i = 0
                    for rec in db.enumerate_records(tab):
                        for field, fielddef in zip(rec.fields, tab.fields):
                            print(">> %s -- %s" % (fielddef, field.content))
                        i += 1
                        if i > reclimit:
                            break
            except Exception as e:
                print("ERROR: %s" % e)


if __name__ == "__main__":
    main()
