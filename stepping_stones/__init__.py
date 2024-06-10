import os
import signal
import sqlite3
import sys
def my_signal_handler(*args):
    if os.environ.get('RUN_MAIN') == 'true':
        conn = sqlite3.connect("db.sqlite3")
        conn.execute("pragma wal_checkpoint(TRUNCATE);")
        conn.close()
        print('Cleanly shutdown')
    sys.exit(0)

signal.signal(signal.SIGINT, my_signal_handler)