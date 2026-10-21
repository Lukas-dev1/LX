#!/bin/sh
# Runs nettest.py through stdin: `python3 /nettest.py` currently fails with EINVAL under lx (open bug),
# while the same script on stdin works.
python3 - < /nettest.py
