# A script run by path (the usual Python entrypoint): imports from the stdlib and prints where it runs.
import json, os, sys

print("script ran:", sys.version.split()[0], os.getcwd(), json.dumps({"ok": True}))
