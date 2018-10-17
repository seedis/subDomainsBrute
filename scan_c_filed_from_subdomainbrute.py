# -*- coding=utf8 -*-
import os
import sys
import requests
import threading
import Queue
import time
import re
import base64
from requests.auth import HTTPBasicAuth
reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()   #
def get_domain_and_ip(raw_file):   #the domain must include the string of '.com'
	f=open(raw_file,"r")
	domain=[]
	for i in f.readlines():
		url= i[0:i.find(".com")+4]
		#print url
		if ".com" in url:
			domain.append(url.strip())
	ip_list=[]
	ip_list1=[]
	f=open(raw_file,"r")
	for i in f.readlines():
		#ip_s= i[30:].split(",")
		#for ip in ip_s:
		#	ip_list.append(ip.strip())
		ip_list.append(i.strip())
	for ip in sorted(list(set(ip_list))):
		if ip.split(".")[0] in ["10","172","192"]:
			continue
		else:
			ip_list1.append(ip.strip()+"\n")
	f.close()
	ip_c_list=[]
	ip_c_list1=[]
	for i in ip_list1:
		if i.split(".")[0]+"."+i.split(".")[1]+"."+i.split(".")[2]+".1/24" not in ip_c_list:
			ip_c_list.append(i.split(".")[0]+"."+i.split(".")[1]+"."+i.split(".")[2]+".1/24")
	for i in ip_c_list:
		ip_c_list1.append(i)
	return domain+ip_c_list1

def handle_ip(ip):
    ip=ip.strip('\'').strip('\"')
    ips=[]
    if '-' in ip:
        ip=ip.split('-')
        ip1=ip[0].strip()
        ip2=ip[1].strip()
        #print ip
        for i in range(int(ip1.split('.')[3]),int(ip2)+1):
            ips.append(ip1.split('.')[0]+'.'+ip1.split('.')[1]+'.'+ip1.split('.')[2]+'.'+str(i))
        return ips                  
    elif '/' in ip:
        ip=ip.split('/')
        ip1=ip[0].strip()
        ip2=ip[1].strip()
        if ip2=='24':
            ip1=ip1.split('.')
            for i in range(1,255):
                ips.append(ip1[0]+'.'+ip1[1]+'.'+ip1[2]+'.'+str(i))
        if ip2=='16':
            ip1=ip1.split('.')
            for i in range(1,255):
                for j in range(1,255):
                    ips.append(ip1[0]+'.'+ip1[1]+'.'+str(i)+'.'+str(j))
        return ips     
    else:
        ips.append(ip)
        return ips

def convert_ip_to_url(ipss):
	#ports=['80','443','8080','8088','8888','8081','7001']#
	#ports=['80','8080']
	#ports=['9000']
	ports=[]
	for i in range(8081,10000):
		ports.append(str(i));
	urls=[]
	for i in ipss:
		ip__s=[]
		if re.match("[a-zA-Z]+",i):
			ip__s.append(i.strip())
			#print ip__s
			pass
		else:
			ip__s=handle_ip(i.strip())
		for ip in ip__s:
			for port in ports:
				if port=='80':
					urls.append('http://'+ip+'/')
				elif port=='443':
					urls.append('https://'+ip+'/')
				else:
					urls.append('http://'+ip+':'+port+'/')
					urls.append('https://'+ip+':'+port+'/')
	return urls



if len(sys.argv) == 1:
    msg = """
Usage: XXX.py file.txt
scan the c_field website's title from a subdomainbrute's file
"""
    print msg
    sys.exit(0)


class Scanner(object):
	def __init__(self):
		self.raw_file = sys.argv[-1]
		self.queue = Queue.Queue()
		self.ip_doamin=get_domain_and_ip(self.raw_file)
		self.url_all=convert_ip_to_url(self.ip_doamin)
		for i in self.url_all:
			self.url=i.strip().replace("\r\n","")
			self.queue.put(self.url)
		self.lock = threading.Lock()
		self.thread_count = 2000
		self.STOP_ME = False
	def _print(self, msg):
		self.lock.acquire()
		#print msg
		self.lock.release()

	def scan_url(self):   #svn solr uddi tomcat jenkins 
		while not self.STOP_ME:
			try:
			    url = self.queue.get(timeout=0.5)
			except:
				break
			self.title_scan(url)
		self.exit_thread()
	def title_scan(self,url):
		url1=url
		try:
			r=requests.get(url1,headers={'User-Agent': 'Mozilla/4.0'},verify=False,timeout=3)
			#print (r.status if("46" in url1) else NULL)
			#print url1,r.status
			if (r.status_code==200) or (r.status_code /100==3):
				if re.findall('<title>(.*)</title>', r.content):
					title = re.findall('<title>(.*)</title>', r.content)[0]
				else:
					title = None
				print r.url.strip()+"  ---"+str(len(r.content))+"---"+str(title)+"\r\n"
				f1=open("title1.txt","a")
				f1.write(r.url.strip()+"  ---"+str(len(r.content))+"---"+str(title)+"\r\n")
				f1.close()
			else:
				pass
		except Exception,e:
			pass#print str(e),url1,'\r\n'
	def exit_thread(self):
		self.lock.acquire()
		self.thread_count -= 1
		self.lock.release()
	def scan(self):
		for i in range(self.thread_count):
			t = threading.Thread(target=self.scan_url)
			t.start()

s = Scanner()
s.scan()
try:
	while s.thread_count > 0:
		time.sleep(0.0001)
except KeyboardInterrupt, e:
	s.STOP_ME = True
	time.sleep(1.0)
	print 'User Aborted.'