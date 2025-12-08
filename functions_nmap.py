from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import os, re, json, hashlib, time, shutil, subprocess

def nmap_scaninfo(request):
	tmpfiles = os.listdir('/tmp/')

	res = {'out':[], 'scans':{}}

	for ff in tmpfiles:
		if re.search(r'\.xml.active$', ff) is not None:
			f = ff[0:-7]
			res['scans'][f] = {'status':'active'}
			try:
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

							# Attempt to move the file if it's marked as finished but still in /tmp
							# This handles cases where the background shell command's 'mv' failed or didn't run.
							try:
								# ff is filename.active (e.g. scan.xml.active)
								# We want to move it to /opt/xml/scan.xml
								# Since ff includes .active, removing the last 7 chars gives filename.xml?
								# No, f = ff[0:-7] is the prefix.
								# Wait, ff is "my_scan.xml.active". f is "my_scan.xml".
								# But let's be careful.
								# If filename was "my_scan.xml", nmap used "/tmp/my_scan.xml.active".
								# So target is /opt/xml/ + f.
								src = '/tmp/' + ff
								dst = '/opt/xml/' + f
								shutil.move(src, dst)
							except Exception as e:
								# If move fails, we can't do much, but logging/ignoring prevents crash.
								pass
			except Exception:
				pass

	return HttpResponse(json.dumps(res, indent=4), content_type="application/json")

def nmap_newscan(request):
	if request.method == "POST":
		if(re.search(r'^[a-zA-Z0-9\_\-\.]+$', request.POST['filename']) and re.search(r'^[a-zA-Z0-9\-\.\:\=\s,]+$', request.POST['params']) and re.search(r'^[a-zA-Z0-9\-\.\:\/\s]+$', request.POST['target'])):
			res = {'p':request.POST}

			# Ensure we use absolute path for nmap if possible, or assume it's in PATH.
			nmap_bin = 'nmap'
			if os.path.exists('/usr/bin/nmap'):
				nmap_bin = '/usr/bin/nmap'
			elif os.path.exists('/usr/local/bin/nmap'):
				nmap_bin = '/usr/local/bin/nmap'

			# Construct the command
			# We use subprocess via shell for background execution logic, but cleaner.
			# Actually, sticking to the shell string with explicit redirects is safer for async execution without hanging.

			cmd = '({nmap} {params} --script={script_dir} -oX /tmp/{filename}.active {target} > /tmp/nmap_scan.log 2>&1; mv /tmp/{filename}.active /opt/xml/{filename} >> /tmp/nmap_scan.log 2>&1) &'.format(
				nmap=nmap_bin,
				params=request.POST['params'],
				script_dir=settings.BASE_DIR + '/nmapreport/nmap/nse/',
				filename=request.POST['filename'],
				target=request.POST['target']
			)

			# Log the command to stdout so user can see it in Railway logs
			print("Executing scan command: " + cmd)

			subprocess.Popen(cmd, shell=True)

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
