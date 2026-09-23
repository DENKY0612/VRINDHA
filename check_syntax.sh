#!/bin/bash
cd /mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND
python3 -c 'import py_compile; py_compile.compile("vrin_SOC/core/daily_talk.py", doraise=True); py_compile.compile("vrin_SOC/core/startup_context.py", doraise=True); print("OK")'
