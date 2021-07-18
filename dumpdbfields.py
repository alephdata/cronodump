import os
import os.path
from crodump.Database import Database
from crodump.hexdump import asasc

class Cls: pass

def main():
    import sys
    dbpath = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.getenv("HOME"), "prj/cronos")
    args = Cls()
    args.verbose = False

    for path, _, files in os.walk(dbpath):
        if any(_ for _ in files if _.lower()=="crostru.dat"):
            print(path)

            db = Database(path)
            for tab in db.enumerate_tables():
                tab.dump(args)
                print("nr=%d" % db.nrofrecords())
                i = 0
                for sysnum, rec in db.enumerate_records(tab):
                    # beware to skip tab.fields[0], which is the 'sysnum'
                    # since the rec does not include the sysnum.
                    print(">> %s -- %s" % (tab.fields[0], sysnum))
                    for field, fielddef in zip(rec, tab.fields[1:]):
                        print(">> %s -- %s" % (fielddef, asasc(field)))
                    i += 1
                    if i>100: break


if __name__=="__main__":
    main()

