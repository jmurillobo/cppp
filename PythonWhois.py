# -*- encoding: utf-8 -*-
'''
Notas:
Lib: https://pypi.python.org/pypi/pythonwhois
'''
import pythonwhois
import sys

if len(sys.argv) != 2:
    print "[-] usage python PythonWhoisExample.py <domain_name>"
    sys.exit()

whois = pythonwhois.get_whois(sys.argv[1])
for key in whois.keys():
    print "[+] %s : %s \n" %(key, whois[key])
