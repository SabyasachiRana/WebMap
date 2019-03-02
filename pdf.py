from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
from collections import OrderedDict
from nmapreport.functions import *
#from view import labelToColor

def reportPDFView(request):
	r = { 'out':'' }

	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True

	filterscriptid = {
	}

	if 'scanfile' in request.session:
		oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
		r['out2'] = json.dumps(oo['nmaprun'], indent=4)
		o = json.loads(r['out2'])
	else:
		return HttpResponse('error: scan file not loaded', content_type="text/html")	

	r['html'] = ''
	hostdetails = ''
	counters = {'po':0,'pc':0,'pf':0,'hostsup':0,'ostype':{},'pi':{},'ss':{}}

	scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	# collect all cve in cvehost dict
	cvehost = get_cve(scanmd5)
	r['toc'] = '<h3>Table of contents</h3><div class="container">'

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		hostcounters = {'po':0,'pc':0,'pf':0,'ostype':{},'pi':{},'ss':{}}
		hostdetails_html = ''
		portsfound = False
		striggered = False
		lastportid = 0

		saddress = 'noaddress'

		if '@addr' in i['address']:
			saddress = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					saddress = ai['@addr'] 

		addressmd5 = hashlib.md5(str(saddress).encode('utf-8')).hexdigest()

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

		if i['status']['@state'] == 'up':
			r['toc'] += '<b>'+saddress+'</b><br>&nbsp; <a href="#addr'+addressmd5+'">Port scan</a><br>'
			labelout = ''
			if scanmd5 in labelhost:
				if addressmd5 in labelhost[scanmd5]:
					labelcolor = labelToColor(labelhost[scanmd5][addressmd5])
					# labelmargin = labelToMargin(labelhost[scanmd5][addressmd5])
					labelout = '<span style="" class="label '+labelcolor+'">'+html.escape(labelhost[scanmd5][addressmd5])+'</span>'

			hostdetails_html += '<div style="page-break-before: always;">'
			hostdetails_html += '	<h2 id="addr'+addressmd5+'">'+html.escape(saddress)+' '+labelout+'</h2> '

			hostdetails_html += '	<span class="subtitle">Status: '+html.escape(i['status']['@state'])+', '
			hostdetails_html += 'Reason: '+html.escape(i['status']['@reason'])+', '
			hostdetails_html += 'TTL: '+html.escape(i['status']['@reason_ttl'])+'</span>'

			if 'hostsup' in counters:
				counters['hostsup'] = (counters['hostsup'] + 1)
			else:
				counters['hostsup'] = 1

		hostdetails_html_tr = ''
		portdetails_html_tr = ''
		if 'ports' in i and 'port' in i['ports']:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if p['@portid'] != lastportid:
					lastportid = p['@portid']
				else:
					continue;

				hdhtml_stateico = ''
				if p['state']['@state'] == 'closed':
					hdhtml_stateico = '<i class="fas fa-door-closed red-text"></i>'
					counters['pc'] = (counters['pc'] + 1)
					hostcounters['pc'] = (hostcounters['pc'] + 1)
				elif p['state']['@state'] == 'open':
					hdhtml_stateico = '<i class="fas fa-door-open green-text"></i>'
					counters['po'] = (counters['po'] + 1)
					hostcounters['po'] = (hostcounters['po'] + 1)
				elif p['state']['@state'] == 'filtered':
					hdhtml_stateico = '<i class="fas fa-filter grey-text"></i>'
					counters['pf'] = (counters['pf'] + 1)
					hostcounters['pf'] = (hostcounters['pf'] + 1)

				if 'service' in p:
					if '@ostype' in p['service']:
						if p['service']['@ostype'] in counters['ostype']:
							counters['ostype'][p['service']['@ostype']] = (counters['ostype'][p['service']['@ostype']] +1)
						else:
							counters['ostype'][p['service']['@ostype']] = 1;

					if p['service']['@name'] in counters['ss']:
						counters['ss'][p['service']['@name']] = (counters['ss'][p['service']['@name']] + 1)
					else:
						counters['ss'][p['service']['@name']] = 1

				if p['@portid'] in counters['pi']:
					counters['pi'][p['@portid']] = (counters['pi'][p['@portid']] + 1)
				else:
					counters['pi'][p['@portid']] = 1

				hdhtml_product = ''
				if 'service' in p:
					if '@product' in p['service']:
						hdhtml_product = html.escape(p['service']['@product'])
					else:
						hdhtml_product = '<i class="grey-text">No Product</i>'

				hdhtml_version = ''
				if 'service' in p:
					if '@version' in p['service']:
						hdhtml_version = html.escape(p['service']['@version'])
					else:
						hdhtml_version = '<i class="grey-text">No Version</i>'

				hdhtml_protocolor = 'grey'
				if p['@protocol'] == 'tcp':
					hdhtml_protocolor = 'blue'
				elif p['@protocol'] == 'udp':
					hdhtml_protocolor = 'red'

				if 'service' in p:
					servicename = p['service']['@name']
				else:
					servicename = ''
				
				hostdetails_html_tr += '<tr>'+\
				'	<td><span class="'+hdhtml_protocolor+'-text">'+p['@protocol']+'</span> / <span class=""><b>'+p['@portid']+'</b></span><br><span class="small">'+servicename+'</span></td>'+\
				'	<td>'+hdhtml_stateico+' '+p['state']['@state']+'</td>'+\
				'	<td>'+hdhtml_product+' / '+hdhtml_version+'</td>'+\
				'</tr>'

				if 'script' in p:
					lastscript = ''
					for ii in p['script']:
						if type(ii) is dict:
							script = ii
						else:
							script = p['script']

						if lastscript != script['@id']:
							lastscript = script['@id']
						else:
							continue

						if script['@output'].replace('\n','') != '' and script['@id'] not in filterscriptid:
							portdetails_html_tr += '<div class="extratitle"><b class="red-text">'+html.escape(script['@id'])+'</b> - Address: <b>'+html.escape(saddress)+'</b> - Port: <b>'+p['@portid']+'</b></div>'+\
							'<div class="extrainfo">'+html.escape(script['@output']).replace('\n','<br>')+'</div>'

				portsfound = True

		notesout,notesb64 = '',''
		if scanmd5 in noteshost:
			if addressmd5 in noteshost[scanmd5]:
				notesb64 = noteshost[scanmd5][addressmd5]
				notesout = '<div style="page-break-before: always;">'+\
				'	<h3 id="notes'+addressmd5+'">Notes for host '+saddress+'</h3>'+\
				'	'+base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')+\
				'</div>'
				r['toc'] += '&nbsp; &nbsp; &nbsp; &nbsp; <a href="#notes'+addressmd5+'">Notes</a><br>'


		cveout,cveout_html = '',''
		if scanmd5 in cvehost:
			if addressmd5 in cvehost[scanmd5]:
				#for cveport in cvehost[scanmd5][addressmd5]:
				cvejson = json.loads(cvehost[scanmd5][addressmd5])
				for ic in cvejson:
					if type(ic) is list:
						listcve = ic
					elif type(ic) is dict:
						listcve = [ic]

					for cveobj in listcve:	
						cverefout = ''
						for cveref in cveobj['references']:
							cverefout += '<a href="'+cveref+'">'+cveref+'</a><br>'

						cveexdbout = ''
						if 'exploit-db' in cveobj:
							cveexdbout = '<br><div class="small" style="line-height:20px;"><b>Exploit DB:</b><br>'
							for cveexdb in cveobj['exploit-db']:
								if 'title' in cveexdb:
									cveexdbout += '<a href="'+cveexdb['source']+'">'+html.escape(cveexdb['title'])+'</a><br>'
							cveexdbout += '</div>'

						cveout += '<div style="line-height:28px;padding:10px;margin-top:10px;border-bottom:solid #ccc 1px;">'+\
						'	<span class="label red">'+html.escape(cveobj['id'])+'</span> '+html.escape(cveobj['summary'])+'<br><br>'+\
						'	<div class="small" style="line-height:20px;"><b>References:</b><br>'+cverefout+'</div>'+\
						cveexdbout+\
						'</div>'

				r['toc'] += '&nbsp; &nbsp; &nbsp; &nbsp; <a href="#cvelist'+addressmd5+'">CVE List</a><br>'

				cveout_html = '<div style="page-break-before: always;">'+\
				'	<h3 id="cvelist'+addressmd5+'">CVE List for '+saddress+':</h3>'+\
				cveout+\
				'</div>'

		if i['status']['@state'] == 'up':
			hostdetails_html += '<div class="row margintb">'+\
			'		<div class="col s3"><center><h3><i class="fab fa-creative-commons-sampling"></i> '+str(hostcounters['po']+hostcounters['pc']+hostcounters['pf'])+'</h3>TOTAL PORT</center></div>'+\
			'		<div class="col s3 bleft""><center><h3><i class="fas fa-door-open green-text"></i> '+str(hostcounters['po'])+'</h3>OPEN PORT</center></div>'+\
			'		<div class="col s3 bleft"><center><h3><i class="fas fa-door-closed red-text"></i> '+str(hostcounters['pc'])+'</h3>CLOSED PORT</center></div>'+\
			'		<div class="col s3 bleft"><center><h3><i class="fas fa-filter grey-text"></i> '+str(hostcounters['pf'])+'</h3>FILTERED PORT</center></div>'+\
			'	</div>'+\
			'	<table><thead><tr><th>Protocol / Port</th><th>Port State</th><th>Product / Version</th></tr></thead><tbody>'+\
			hostdetails_html_tr+\
			'</tbody></table></div>'+\
			'<div style="page-break-before: always;"><h3>NSE Scripts for '+saddress+':</h3>'+portdetails_html_tr+'</div>'+\
			notesout+\
			cveout_html

		if portsfound is True:
			# r['out'] += '1,'
			hostdetails += hostdetails_html
		#else:
		#	r['out'] += '0,'

		# this fix single host report
		if type(ik) is not dict:
			break;


	html_ports = ''
	javascript_ports = ''
	for ii in counters['pi']:
		html_ports += '<b>'+str(ii)+'</b> <span class="grey-text">('+str(counters['pi'][ii])+')</span>, '
		javascript_ports += '["'+str(ii)+'", '+str(counters['pi'][ii])+'],'

	html_services = ''
	javascript_services = ''
	for ii in counters['ss']:
		html_services += '<b>'+str(ii)+'</b> <span class="grey-text">('+str(counters['ss'][ii])+')</span>, '
		javascript_services += '["'+str(ii)+'", '+str(counters['ss'][ii])+'],'

	scantitle = request.session['scanfile'].replace('.xml','').replace('_',' ')
	if re.search('^webmapsched\_[0-9\.]+', request.session['scanfile']):
		m = re.search('^webmapsched\_[0-9\.]+\_(.+)', request.session['scanfile'])
		scantitle = m.group(1).replace('.xml','').replace('_',' ')

	scantype = ''
	if 'scaninfo' in o and '@type' in o['scaninfo']:
		scantype = o['scaninfo']['@type']

	if 'scaninfo' in o and type(o['scaninfo']) is list:
		for sinfo in o['scaninfo']:
			scantype += sinfo['@type']+', '
		scantype = scantype[0:-2]

	protocol = ''
	if 'scaninfo' in o and '@protocol' in o['scaninfo']:
		protocol = o['scaninfo']['@protocol']

	if 'scaninfo' in o and type(o['scaninfo']) is list:
		for sinfo in o['scaninfo']:
			protocol += sinfo['@protocol']+', '
		protocol = protocol[0:-2]

	r['html'] += '<script type="text/javascript" src="https://www.google.com/jsapi?autoload={%27modules%27:[{%27name%27:%27visualization%27,%27version%27:%271.1%27,%27packages%27:[%27corechart%27,%27sankey%27,%27annotationchart%27]}]}"></script>'+\
	'<div class="container"><div style="text-align:center;width:100%;">'+\
	'	<img src="/static/logoblack.png" style="height:60px;" />'+\
	'	<h1 style="margin-top:300px;">Port Scan Report</h1>'+\
	'	<span class="subtitle">'+html.escape(scantitle)+'</span><br>'+\
	'	<div style="margin-top:200px;font-size:18px;padding:20px;"><table class="striped">'+\
	'	<thead>'+\
	'		<tr><th style="min-width:200px;">&nbsp;</th><th></th></tr>'+\
	'	</thead>'+\
	'	<tbody>'+\
	'		<tr><td><b>Arguments:</b></td><td>'+html.escape(o['@args'])+'</td></tr>'+\
	'		<tr><td><b>Scan started at:</b></td><td>'+html.escape(o['@startstr'])+'</td></tr>'+\
	'		<tr><td><b>Scan type:</b></td><td>'+html.escape(scantype)+'</td></tr>'+\
	'		<tr><td><b>Nmap version:</b></td><td>'+html.escape(o['@version'])+'</td></tr>'+\
	'	</tbody></table></div>'+\
	'	<div style="color:#999;margin-top:100px;font-size:18px;"><i>The information contained in these documents is confidential, privileged and only for the information of the intended recipient and may not be used, published or redistributed.</i></div>'+\
	'</div></div><br>'+\
	'<!-- <div style="page-break-before: always;">'+\
	r['toc']+\
	'</div> --> '+\
	'<div style="page-break-before: always;">'+\
	'	<h2>Ports and Services</h2><div class="subtitle">Ports status and services type</div>'+\
	'	<div class="row" style="margin-top:30px;border-bottom:solid #ccc 1px;padding:10px;">'+\
	'		<div class="col s3"><b class="blue-text" style="font-size:24px;">HOSTS UP</b><br><span style="color:#999;font-size:32px;">'+str(counters['hostsup'])+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">PORTS</b><br><span style="color:#999;font-size:32px;">'+str(counters['pc']+counters['po']+counters['pf'])+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">SERVICES</b><br><span style="color:#999;font-size:32px;">'+str(len(counters['ss'].keys()))+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">OS</b><br><span style="color:#999;font-size:32px;">'+str(len(counters['ostype'].keys()))+'</span></div>'+\
	'	</div>'+\
	'	<div class="row" style="margin-top:50px;">'+\
	'		<div class="col s8">'+\
	'			<div style="width:400px;height:300px;" id="chart_portstatus"></div>'+\
	'			<div style="width:400px;height:300px;" id="chart_ports"></div>'+\
	'			<div style="width:400px;height:300px;" id="chart_services"></div>'+\
	'		</div>'+\
	'		<div class="col s4" style="border-left:solid #ccc 1px;padding-left:20px;min-height:300px;">'+\
	'			<b class="subtitle">Total Ports</b><br><span class="subtitle">'+str(counters['pc']+counters['po']+counters['pf'])+'</span><br><br>'+\
	'			<b class="subtitle green-text">Open Ports</b><br><span class="subtitle green-text">'+str(counters['po'])+'</span><br><br>'+\
	'			<b class="subtitle red-text">Closed Ports</b><br><span class="subtitle red-text">'+str(counters['pc'])+'</span><br><br>'+\
	'			<b class="subtitle orange-text">Filtered Ports</b><br><span class="subtitle orange-text">'+str(counters['pf'])+'</span><br><br>'+\
	'			<b>Ports</b>:<br><span style="font-family:monospace;font-size:11px;">'+html_ports[0:-2]+'</span><br><br>'+\
	'			<b>Services</b>:<br><span style="font-family:monospace;font-size:11px;">'+html_services[0:-2]+'</span>'+\
	'		</div>'+\
	'</div>'

	r['html'] += '<script type="text/javascript">'+\
	'$(document).ready(function() {'+\
	'	drawChart();'+\
	'});'+\
	'function drawChart() {'+\
	'	var data = new google.visualization.DataTable();'+\
	'	data.addColumn("string", "State");'+\
	'	data.addColumn("number", "Count");'+\
	'	data.addRows(['+\
	'		["Open", '+str(counters['po'])+'],'+\
	'		["Closed", '+str(counters['pc'])+'],'+\
	'		["Filtered", '+str(counters['pf'])+'],'+\
	'	]);'+\
	'	var options = {'+\
	'		"title":"Port Status",'+\
	'		"width":500,'+\
	'		"height":300,'+\
	'		"is3D": true,'+\
	'		chartArea: {width:"100%",height:"90%"},'+\
	'		"legend": {'+\
	'			"position": "labeled"'+\
	'		}'+\
	'	};'+\
	'	var chart = new google.visualization.PieChart(document.getElementById("chart_portstatus"));'+\
	'	chart.draw(data, options);'+\
	''+\
	'	var data = new google.visualization.DataTable();'+\
	'	data.addColumn("string", "Ports");'+\
	'	data.addColumn("number", "Count");'+\
	'	data.addRows(['+\
	javascript_ports+\
	'	]);'+\
	'	var options = {'+\
	'		"title":"Ports list",'+\
	'		"width":500,'+\
	'		"height":300,'+\
	'		"is3D": true,'+\
	'		chartArea: {width:"100%",height:"90%"},'+\
	'		"legend": {'+\
	'			"position": "labeled"'+\
	'		}'+\
	'	};'+\
	'	var chart = new google.visualization.PieChart(document.getElementById("chart_ports"));'+\
	'	chart.draw(data, options);'+\
	''+\
	'	var data = new google.visualization.DataTable();'+\
	'	data.addColumn("string", "Ports");'+\
	'	data.addColumn("number", "Count");'+\
	'	data.addRows(['+\
	javascript_services+\
	'	]);'+\
	'	var options = {'+\
	'		"title":"Services list",'+\
	'		"width":500,'+\
	'		"height":300,'+\
	'		"is3D": true,'+\
	'		chartArea: {width:"100%",height:"90%"},'+\
	'		"legend": {'+\
	'			"position": "labeled"'+\
	'		}'+\
	'	};'+\
	'	var chart = new google.visualization.PieChart(document.getElementById("chart_services"));'+\
	'	chart.draw(data, options);'+\
	'}'+\
	'</script>'

	r['html'] += hostdetails

	r['html'] += ''+\
	'<div style="page-break-before: always;">'+\
	'	<div>'+\
	'		<div style="text-align:center;padding-top:600px;"><b>Generated by</b><br>'+\
	'			<img src="/static/logoblack.png" style="height:60px;" /><br>'+\
	'			<a href="https://github.com/Rev3rseSecurity/WebMap">https://github.com/Rev3rseSecurity/WebMap</a>'+\
	'		</div>'+\
	'	</div>'+\
	'</div>'

	return render(request, 'nmapreport/report.html', r)


