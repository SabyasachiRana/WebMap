from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, requests, base64, urllib.parse
from collections import OrderedDict
from nmapreport.functions import *

def rmNotes(request, hashstr):
	if 'auth' not in request.session:
		return False

	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
	if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
		os.remove('/opt/notes/'+scanfilemd5+'_'+hashstr+'.notes')
		res = {'ok':'notes removed'}
	else:
		res = {'error':'invalid format'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def saveNotes(request):
	if 'auth' not in request.session:
		return False

	if request.method == "POST":
		scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

		if re.match('^[a-f0-9]{32,32}$', request.POST['hashstr']) is not None:
			f = open('/opt/notes/'+scanfilemd5+'_'+request.POST['hashstr']+'.notes', 'w')
			f.write(request.POST['notes'])
			f.close()
			res = {'ok':'notes saved'}
	else:
		res = {'error': request.method }

	return HttpResponse(json.dumps(res), content_type="application/json")

def rmlabel(request, objtype, hashstr):
	if 'auth' not in request.session:
		return False

	types = {
		'host':True,
		'port':True
	}

	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
		os.remove('/opt/notes/'+scanfilemd5+'_'+hashstr+'.'+objtype+'.label')
		res = {'ok':'label removed'}
		return HttpResponse(json.dumps(res), content_type="application/json")

def label(request, objtype, label, hashstr):
	labels = {
		'Vulnerable':True,
		'Critical':True,
		'Warning':True,
		'Checked':True
	}

	types = {
		'host':True,
		'port':True
	}

	scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	if label in labels and objtype in types:
		if re.match('^[a-f0-9]{32,32}$', hashstr) is not None:
			f = open('/opt/notes/'+scanfilemd5+'_'+hashstr+'.'+objtype+'.label', 'w')
			f.write(label)
			f.close()
			res = {'ok':'label set', 'label':str(label)}
			return HttpResponse(json.dumps(res), content_type="application/json")

def port_details(request, address, portid):
	r = {}

	if 'auth' not in request.session:
		return False

	oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
	r['out'] = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r['out'])

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		if '@addr' in i['address']:
			saddress = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					saddress = ai['@addr'] 

		if str(saddress) == address:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if p['@portid'] == portid:
					return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

def genPDF(request):
	if 'auth' not in request.session:
		return False

	if 'scanfile' in request.session:
		pdffile = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
		if os.path.exists('/opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf'):
			os.remove('/opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf')

		os.popen('/opt/wkhtmltox/bin/wkhtmltopdf --cookie sessionid '+request.session._session_key+' --enable-javascript --javascript-delay 6000 http://127.0.0.1:8000/view/pdf/ /opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf')
		res = {'ok':'PDF created', 'file':'/static/'+pdffile+'.pdf'}
		return HttpResponse(json.dumps(res), content_type="application/json")

def getCVE(request):
	res = {}

	if 'auth' not in request.session:
		return False

	if request.method == "POST":
		scanfilemd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
		cveproc = os.popen('python3 /opt/nmapdashboard/nmapreport/nmap/cve.py '+request.session['scanfile'])
		res['cveout'] = cveproc.read()
		cveproc.close()

		return HttpResponse(json.dumps(res), content_type="application/json")

		#hostmd5 = hashlib.md5(str(request.POST['host']).encode('utf-8')).hexdigest()
		#portmd5 = hashlib.md5(str(request.POST['port']).encode('utf-8')).hexdigest()

		# request.POST['host']

		cpe = json.loads(base64.b64decode(urllib.parse.unquote(request.POST['cpe'])).decode('ascii'))

		for cpestr in cpe:
			r = requests.get('http://cve.circl.lu/api/cvefor/'+cpestr)
			cvejson = r.json()

			for host in cpe[cpestr]:
				hostmd5 = hashlib.md5(str(host).encode('utf-8')).hexdigest()
				if type(cvejson) is list and len(cvejson) > 0:
					res[host] = cvejson[0]
					f = open('/opt/notes/'+scanfilemd5+'_'+hostmd5+'.cve', 'w')
					f.write(json.dumps(cvejson))
					f.close()

		return HttpResponse(json.dumps(res), content_type="application/json")

		r = requests.get('http://cve.circl.lu/api/cvefor/'+request.POST['cpe'])

		if request.POST['host'] not in res:
			res[request.POST['host']] = {}

		cvejson = r.json()

		if type(cvejson) is list and len(cvejson) > 0:
			res[request.POST['host']][request.POST['port']] = cvejson[0]
			f = open('/opt/notes/'+scanfilemd5+'_'+hostmd5+'.cve', 'w')
			f.write(json.dumps(cvejson))
			f.close()

		return HttpResponse(json.dumps(res), content_type="application/json")

def apiv1_hostdetails(request, scanfile, faddress=""):
	if token_check(request.GET['token']) is not True:
		return HttpResponse(json.dumps({'error':'invalid token'}, indent=4), content_type="application/json")

	oo = xmltodict.parse(open('/opt/xml/'+scanfile, 'r').read())
	out2 = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(out2)

	r = {'file':scanfile, 'hosts': {}}
	scanmd5 = hashlib.md5(str(scanfile).encode('utf-8')).hexdigest()

	# collect all labels in labelhost dict
	labelhost = {}
	labelfiles = os.listdir('/opt/notes')
	for lf in labelfiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.host\.label$', lf)
		if m is not None:
			if m.group(1) not in labelhost:
				labelhost[m.group(1)] = {}
			labelhost[m.group(1)][m.group(2)] = open('/opt/notes/'+lf, 'r').read()

	# collect all notes in noteshost dict
	noteshost = {}
	notesfiles = os.listdir('/opt/notes')
	for nf in notesfiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.notes$', nf)
		if m is not None:
			if m.group(1) not in noteshost:
				noteshost[m.group(1)] = {}
			noteshost[m.group(1)][m.group(2)] = open('/opt/notes/'+nf, 'r').read()

	# collect all cve in cvehost dict
	cvehost = get_cve(scanmd5)

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		hostname = {}
		if 'hostnames' in i and type(i['hostnames']) is dict:
			# hostname = json.dumps(i['hostnames'])
			if 'hostname' in i['hostnames']:
				# hostname += '<br>'
				if type(i['hostnames']['hostname']) is list:
					for hi in i['hostnames']['hostname']:
						hostname[hi['@type']] = hi['@name']
				else:
					hostname[i['hostnames']['hostname']['@type']] = i['hostnames']['hostname']['@name'];

		if i['status']['@state'] == 'up':
			po,pc,pf = 0,0,0
			ss,pp,ost = {},{},{}
			lastportid = 0

			if '@addr' in i['address']:
				address = i['address']['@addr']
			elif type(i['address']) is list:
				for ai in i['address']:
					if ai['@addrtype'] == 'ipv4':
						address = ai['@addr']

			if faddress != "" and faddress != address:
				continue

			addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
			#cpe[address] = {}

			labelout = ''
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelout = labelhost[scanmd5][addressmd5]

			notesout,notesb64,removenotes = '','',''
			if scanmd5 in noteshost:
				if addressmd5 in noteshost[scanmd5]:
					notesb64 = noteshost[scanmd5][addressmd5]
			#		notesout = '<br><a id="noteshost'+str(hostindex)+'" href="#!" onclick="javascript:openNotes(\''+hashlib.md5(str(address).encode('utf-8')).hexdigest()+'\', \''+notesb64+'\');" class="small"><i class="fas fa-comment"></i> contains notes</a>'
			#		removenotes = '<li><a href="#!" onclick="javascript:removeNotes(\''+addressmd5+'\', \''+str(hostindex)+'\');">Remove notes</a></li>'

			cveout = ''
			#cvecount = 0
			if scanmd5 in cvehost:
				if addressmd5 in cvehost[scanmd5]:
					cveout = json.loads(cvehost[scanmd5][addressmd5])
			#		for cveobj in cvejson:	
			#			cvecount = (cvecount + 1)


			if faddress == "":
				r['hosts'][address] = {'hostname':hostname, 'label':labelout, 'notes':notesb64}
			else:
				r['hosts'][address] = {'ports':[], 'hostname':hostname, 'label':labelout, 'notes':notesb64, 'CVE':cveout}

			if 'ports' in i and 'port' in i['ports']:
				for pobj in i['ports']['port']:
					if type(pobj) is dict:
						p = pobj
					else:
						p = i['ports']['port']

					if lastportid == p['@portid']:
						continue
					else:
						lastportid = p['@portid']

					v,z,e='','',''
					pp[p['@portid']] = p['@portid']

					servicename = ''
					if 'service' in p:
						ss[p['service']['@name']] = p['service']['@name']

						if '@version' in p['service']:
							v = p['service']['@version']

						if '@product' in p['service']:
							z = p['service']['@product']

						if '@extrainfo' in p['service']:
							e = p['service']['@extrainfo']

						servicename = p['service']['@name']

					if faddress != "":
						r['hosts'][address]['ports'].append({
							    'port': p['@portid'],
							    'name': servicename,
							   'state': p['state']['@state'],
							'protocol': p['@protocol'],
							  'reason': p['state']['@reason'],
							 'product': z,
							 'version': v,
						  'extrainfo': e
						})

	return HttpResponse(json.dumps(r, indent=4), content_type="application/json")


def apiv1_scan(request):
	r = {}
	if token_check(request.GET['token']) is not True:
		return HttpResponse(json.dumps({'error':'invalid token'}, indent=4), content_type="application/json")

	gitcmd = os.popen('cd /opt/nmapdashboard/nmapreport && git rev-parse --abbrev-ref HEAD')
	r['webmap_version'] = gitcmd.read().strip()

	xmlfiles = os.listdir('/opt/xml')

	r['scans'] = {}

	xmlfilescount = 0
	for i in xmlfiles:
		if re.search('\.xml$', i) is None:
			continue

		xmlfilescount = (xmlfilescount + 1)

		try:
			oo = xmltodict.parse(open('/opt/xml/'+i, 'r').read())
		except:
			r['scans'][i] = {'filename':html.escape(i), 'startstr': '', 'nhost':0, 'port_stats':{'open':0,'closed':0,'filtered':0}}
			continue

		rout = json.dumps(oo['nmaprun'], indent=4)
		o = json.loads(rout)

		if 'host' in o:
			if type(o['host']) is not dict:
				hostnum = str(len(o['host']))
			else:
				hostnum = '1'
		else:
			hostnum = '0'

		portstats = nmap_ports_stats(i)

		r['scans'][i] = {'filename':html.escape(i), 'startstr': html.escape(o['@startstr']), 'nhost':hostnum, 'port_stats':{'open':portstats['po'],'closed':portstats['pc'],'filtered':portstats['pf']}}

	return HttpResponse(json.dumps(r, indent=4), content_type="application/json")

