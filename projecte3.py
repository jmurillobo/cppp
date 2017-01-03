# -*- encoding: utf-8 -*-
import whois
import getpass
import sys
import os
reload(sys)
sys.setdefaultencoding('utf8')

#dns utilities
import dns
import dns.resolver
import dns.query
import dns.zone

#geolocalizacion
import pygeoip
import pprint

#nmap
import nmap

# busqueda shodan
import shodan

# request http
import urllib, requests



shodanKeyString = open('shodanKey.txt').readline().rstrip('\n')

def shodanKeyInfo():
    try:
        shodanApi = shodan.Shodan(shodanKeyString)
        info = shodanApi.info()
        for inf in info:
            print '%s: %s ' %(inf, info[inf])
    except shodan.APIError, e:
        print 'Error: %s' % e

def shodanSimpleSearch():
    try:
        shodanApi = shodan.Shodan(shodanKeyString)
        results = shodanApi.search(dominio)
        for result in results:
            print '%s: %s ' %(result, results[result])
            fd.write ('%s: %s \n' %(result, results[result]))
    except shodan.APIError, e:
        print 'Error: %s' % e

def dnsNsRecord():
    try:
        ns1 = dns.resolver.query(str(dominioext), 'NS')
        for i in ns1.response.answer:
            for j in i.items:
                fd.write(" NameServer "+ j.to_text()+ "\n")
        fd.write ("\n")
    except dns.exception.DNSException:
        print 'Error recibiendo registros NS'
        fd.write("Error recibiendo registros NS \n")
        fd.write("\n")
        os.system('kill $PPID')



def dnsTxtRecord():
    try:
        txt1 = dns.resolver.query(str(dominioext), 'TXT')
        for i in txt1.response.answer:
            for j in i.items:
                fd.write(" TXT "+ j.to_text()+ "\n")
        fd.write ("\n")
    except dns.exception.DNSException:
        print 'Error recibiendo registros TXT'
        fd.write("Error recibiendo registros TXT \n")
        fd.write ("\n")

def dnsMxRecord():
    try:
        mx1 = dns.resolver.query(str(dominioext), 'MX')
        for i in mx1.response.answer:
            for j in i.items:
                fd.write(" MX "+ j.to_text()+ "\n")
        fd.write ("\n")
    except dns.exception.DNSException:
        print 'Error recibiendo registros MX'
        fd.write("Error recibiendo registros MX \n")
        fd.write ("\n")


#def dnsARecord():
#    try:
#        a1 = dns.resolver.query(str(dominio), 'A')
#        for i in a1.response.answer:
#            for j in i.items:
#                ip = j.to_text()
#                pprint.pprint(" A "+ j.to_text()+ "\n")
#                fd.write(" A "+ j.to_text()+ "\n")
#        fd.write ("\n")
#        return ip
#    except dns.exception.DNSException:
#        print 'Error recibiendo registros A'
#        fd.write("Error recibiendo registros A \n")
#        fd.write ("\n")

ADDITIONAL_RDCLASS = 65535
name_server = '8.8.8.8'

# ********************************** 1A WHOIS ***********************************************
# Petició de domini a buscar
dominio = getpass.getpass("Dominio a recabar informacion: ")

#if len(dominio) != 2:
#    print "[-] usage python PythonWhois.py <domain_name>"
#    sys.exit()


whois = whois.whois(dominio)
fd = open("dades.txt", "r+")
fd.write ("Datos recogidos por Whois\n")
for key in whois.keys():
    print "[+] %s : %s \n" %(key, whois[key])
    fd.write (""+ str(key)+ " "+ str((whois[key]))+ "\n")


# ********************************** 1B Registres DNS ***********************************************
fd.write ("\n")
fd.write ("\n")
dominiodns = dominio.split(".")[1]
extensidns = dominio.split(".")[2]
dominioext = dominiodns+ "."+ extensidns
print dominioext
fd.write ("Registros DNS obtenidos del dominio "+ str(dominioext) +"\n")

#ns1 = dns.resolver.query(str(dominioext), 'NS')
#for i in ns1.response.answer:
#    for j in i.items:
#        fd.write(" NameServer "+ j.to_text()+ "\n")
#fd.write ("\n")
dnsNsRecord()

#txt1 = dns.resolver.query(str(dominioext), 'TXT')
#for i in txt1.response.answer:
#    for j in i.items:
#        fd.write(" TXT "+ j.to_text()+ "\n")
#fd.write ("\n")
dnsTxtRecord()

#mx1 = dns.resolver.query(str(dominioext), 'MX')
#for i in mx1.response.answer:
#    for j in i.items:
#        fd.write(" MX "+ j.to_text()+ "\n")
#fd.write ("\n")
dnsMxRecord()

a1 = dns.resolver.query(str(dominio), 'A')
for i in a1.response.answer:
    for j in i.items:
        ip = j.to_text()
        pprint.pprint(" A "+ j.to_text()+ "\n")
        fd.write(" A "+ j.to_text()+ "\n")
fd.write ("\n")
#dnsARecord()

# ********************************** 2A Geolocalitzacio DNS ***********************************************
fd.write ("\n")
fd.write ("Datos Geolocalización del dominio "+ str(dominio) +"\n")
gi = pygeoip.GeoIP('GeoLiteCity.dat')

pprint.pprint("Country code: %s " %(str(gi.country_code_by_name(str(dominio)))) )
fd.write ("Country code: %s \n" %(str(gi.country_code_by_name(str(dominio)))) )
pprint.pprint("Full record: %s " %(str(gi.record_by_addr(str(ip)))) )
fd.write ("Full record: %s \n" %(str(gi.record_by_addr(str(ip)))) )
pprint.pprint("Country name: %s " %(str(gi.country_name_by_addr(str(ip)))) )
fd.write ("Country name: %s \n" %(str(gi.country_name_by_addr(str(ip)))) )
pprint.pprint("Timezone: %s " %(str(gi.time_zone_by_addr(str(ip)))) )
fd.write ("Timezone: %s \n" %(str(gi.time_zone_by_addr(str(ip)))) )
fd.write ("\n")


# ********************************** NMAP  ***********************************************
nm = nmap.PortScanner()
nm.scan("'"+ str(ip)+ "'", '22-443')
nm.command_line()
nm.scaninfo()
shodanval = 0

for host in nm.all_hosts():
    print('---------------------------------------------------')
    fd.write('------------Scaneo puertos abiertos---------------------------------------- \n')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    fd.write('Host : %s (%s) \n' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    fd.write('State : %s \n' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        fd.write('Protocol : %s \n' % proto)
        print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            fd.write('port : %s\tstate : %s \n' % (port, nm[host][proto][port]['state']))
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
            if port == 80 or port == 443 or port ==8080:
                shodanval = 1
        if shodanval == 1:
            fd.write ("\n")
            fd.write('------------Scaneo datos Shodan---------------------------------------- \n')
            fd.write ('Datos devueltos por Shodan sobre %s \n' % host)
            shodanSimpleSearch()


# ********************************** Requests Web Page  ***********************************************
fd.write ("\n")
fd.write('------------Requests Web Page---------------------------------------- \n')
response = urllib.urlopen("http://"+ str(dominio))
print "Response Code: "+ str(response.getcode())
fd.write("Response Code: "+str(response.getcode())+ "\n")
print "Response: "+response.read()
fd.write("Response: "+response.read()+ "\n")
print response.geturl()
fd.write(response.geturl()+ "\n")
for header, value in response.headers.items():
    print header+' : '+value
    fd.write(header+' : '+value+ "\n")
responseGet = requests.get("http://"+ str(dominio))
responsePost = requests.post("http://"+ str(dominio))
responsePut = requests.put("http://"+ str(dominio))
responseDelete = requests.delete("http://"+ str(dominio))

print "GET Request. Status code: "+str(responseGet.status_code)
print responseGet.text
fd.write("GET Request. Status code: "+str(responseGet.status_code))
fd.write(responseGet.text+ "\n")

print "POST Request. Status code: "+str(responsePost.status_code)
print responsePost.text
fd.write("POST Request. Status code: "+str(responsePost.status_code))
fd.write(responsePost.text+ "\n")

print "PUT Request. Status code: "+str(responsePut.status_code)
print responsePut.text
fd.write("PUT Request. Status code: "+str(responsePut.status_code))
fd.write(responsePut.text+ "\n")

print "DELETE Request. Status code: "+str(responseDelete.status_code)
print responseDelete.text
fd.write("DELETE Request. Status code: "+str(responseDelete.status_code))
fd.write(responseDelete.text+ "\n")


fd.close()