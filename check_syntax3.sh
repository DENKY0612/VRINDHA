#!/bin/bash
cd /mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND
python3 -c 'import py_compile; py_compile.compile("vrin_SOC/core/secops_prime.py", doraise=True); py_compile.compile("vrin_SOC/core/brain.py", doraise=True); print("OK")'
