# Web-shell checker

The script searches for known web-shells on selected application. It checks, that web-shell script exists on target system, and that it is operational.

# Quickstart

Install dependencies and run
```
# pip3 -r requirements.txt
# python3 web-shell-check.py -u http://test.app
[INFO] Star scanning http://test.app/
[SUCCESS] Web-shell found on http://test.app/xx.php
[INFO] Done scanning http://test.app/
```

