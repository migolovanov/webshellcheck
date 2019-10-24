# Web-shell checker

The script searches for known web-shells on selected application. It checks, that web-shell script exists on target system, and that it is operational.

# Quickstart

Install dependencies and run
```
# pip3 -r requirements.txt
# python3 web-shell-check.py -u http://test.app
[INFO] Star scanning http://127.0.0.1/
[SUCCESS] Web-shell found on http://127.0.0.1/xx.php
[INFO] Done scanning http://127.0.0.1/
```

