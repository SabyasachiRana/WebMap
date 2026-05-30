from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import os, re, json, hashlib, time, shutil, subprocess, threading

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
		filename = request.POST.get('filename', '').strip()
		if not filename:
			filename = 'webmap_scan_' + str(int(time.time())) + '.xml'

		params = request.POST['params'].strip()
		target = request.POST['target'].strip()

		if(re.search(r'^[a-zA-Z0-9\_\-\.]+$', filename) and re.search(r'^[a-zA-Z0-9\-\.\:\=\s,]+$', params) and re.search(r'^[a-zA-Z0-9\-\.\:\/\s]+$', target)):
			res = {'p':request.POST}

			# Ensure we use absolute path for nmap if possible, or assume it's in PATH.
			nmap_bin = 'nmap'
			if os.path.exists('/usr/bin/nmap'):
				nmap_bin = '/usr/bin/nmap'
			elif os.path.exists('/usr/local/bin/nmap'):
				nmap_bin = '/usr/local/bin/nmap'

			# Build a safe argument list instead of using shell=True.
			cmd_args = [nmap_bin] + params.split() + ['--script=' + os.path.join(settings.BASE_DIR, 'nmapreport', 'nmap', 'nse', '')] + ['-oX', '/tmp/' + filename + '.active'] + target.split()
			log_file = '/tmp/nmap_scan.log'
			active_file = '/tmp/' + filename + '.active'
			final_file = '/opt/xml/' + filename

			def run_scan_async(args, stdout_path, active_path, dest_path):
				with open(stdout_path, 'ab') as logfd:
					proc = subprocess.Popen(args, stdout=logfd, stderr=subprocess.STDOUT)
					proc.wait()
				try:
					shutil.move(active_path, dest_path)
				except Exception as e:
					print('Failed to move nmap output file:', e)

			# Launch the scan in a background thread without shell interpolation.
			threading.Thread(target=run_scan_async, args=(cmd_args, log_file, active_file, final_file), daemon=True).start()

			if request.POST['schedule'] == "true":
				schedobj = {'params':request.POST, 'lastrun':time.time(), 'number':0}
				filenamemd5 = hashlib.md5(str(filename).encode('utf-8')).hexdigest()
				writefile = '/opt/schedule/'+filenamemd5+'.json'
				file = open(writefile, "w")
				file.write(json.dumps(schedobj, indent=4))

			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
		else:
			res = {'error':'invalid syntax'}
			return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
