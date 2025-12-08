from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import os, re, json, hashlib, time

def nmap_scaninfo(request):
	tmpfiles = os.listdir('/tmp/')

	res = {'out':[], 'scans':{}}

	for ff in tmpfiles:
		if re.search(r'\.xml.active$', ff) is not None:
			f = ff[0:-7]
			res['scans'][f] = {'status':'active'}
			with open('/tmp/'+ff) as n:
				lines = n.readlines()
				for line in lines:
					#res['out'].append(line.strip())
					# <nmaprun scanner="nmap" args="nmap -oG /tmp/test.grep -oX /tmp/scan.xml -sT -sV -sC -T5 scanme.nmap.org" start="1541780258" startstr="Fri Nov  9 16:17:38 2018" version="7.60" xmloutputversion="1.04">

					rx = re.search(r'args\=.+\-oX \/tmp\/(.+\.xml).+ start\=.+ startstr\=.(.+). version\=', line.strip())
					if rx is not None:
						res['scans'][f]['filename'] = rx.group(1)
						res['scans'][f]['startstr'] = rx.group(2)

					rx = re.search(r'scaninfo type\=.(.+). protocol\=.(.+). numservices', line.strip())
					if rx is not None:
						res['scans'][f]['type'] = rx.group(1)
						res['scans'][f]['protocol'] = rx.group(2)

					# <finished time="1541780323" timestr="Fri Nov  9 16:18:43 2018" elapsed="65.31" summary="Nmap done at Fri Nov  9 16:18:43 2018; 1 IP address (1 host up) scanned in 65.31 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
					rx = re.search(r'finished .+ summary\=.(.+). exit\=', line.strip())
					if rx is not None:
						res['scans'][f]['status'] = 'finished'
						res['scans'][f]['summary'] = rx.group(1)

	return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

def nmap_newscan(request):
	if request.method == "POST":
		if(re.search(r'^[a-zA-Z0-9\_\-\.]+$', request.POST['filename']) and re.search(r'^[a-zA-Z0-9\-\.\:\=\s,]+$', request.POST['params']) and re.search(r'^[a-zA-Z0-9\-\.\:\/\s]+$', request.POST['target'])):
			res = {'p':request.POST}
			# Use parentheses for background execution to ensure logical operators work as expected
			# Redirect output to a log file instead of /dev/null for debugging
			cmd = '(nmap ' + request.POST['params'] + ' --script=' + settings.BASE_DIR + '/nmapreport/nmap/nse/ -oX /tmp/' + request.POST['filename'] + '.active ' + request.POST['target'] + ' > /tmp/nmap_scan.log 2>&1 && ' + \
			'sleep 2 && mv /tmp/' + request.POST['filename'] + '.active /opt/xml/' + request.POST['filename'] + ') &'
			os.popen(cmd)

			if request.POST['schedule'] == "true":
				schedobj = {'params':request.POST, 'lastrun':time.time(), 'number':0}
				filenamemd5 = hashlib.md5(str(request.POST['filename']).encode('utf-8')).hexdigest()
				writefile = '/opt/schedule/'+filenamemd5+'.json'
				file = open(writefile, "w")
				file.write(json.dumps(schedobj, indent=4))

			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
		else:
			res = {'error':'invalid syntax'}
			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
