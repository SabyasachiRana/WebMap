from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
from collections import OrderedDict
from nmapreport.functions import *

def visjs(request):
	r = {}

	if 'auth' not in request.session:
		return render(request, 'nmapreport/nmap_auth.html', r)
	else:
		r['auth'] = True


	if 'scanfile' not in request.session:
		r['js'] = '''
			<script>
			$(document).ready(function() {
				$('.modal').modal();
				$('#mynetwork').remove();
				$('#modaltitle').html('Error');
				$('#modalbody').html(
					'Please, select an Nmap XML Report first.'+
					''
				);
				$('#modalfooter').html('<a href="/" class="btn red">Go to Nmap XML File list</a>');
				setTimeout(function() { $('#modal1').modal('open'); }, 1000);
			});
			</script>
		'''
		return render(request, 'nmapreport/nmap_network.html', r)

	oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
	r['out2'] = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r['out2'])

	scanmd5 = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()

	r['scanfile'] = request.session['scanfile']
	r['scanmd5'] = scanmd5

	addnodes = ''
	portnodes = {}

	for ik in o['host']:
		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		hostname = ''
		if 'hostnames' in i and type(i['hostnames']) is dict:
			if 'hostname' in i['hostnames']:
				hostname += '<br>'
				if type(i['hostnames']['hostname']) is list:
					for hi in i['hostnames']['hostname']:
						hostname += '<span class="small grey-text"><b>'+hi['@type']+':</b> '+hi['@name']+'</span><br>'
				else:
					hostname += '<span class="small grey-text"><b>'+i['hostnames']['hostname']['@type']+':</b> '+i['hostnames']['hostname']['@name']+'</span><br>'

		if i['status']['@state'] == 'up':

			po,pc,pf = 0,0,0
			#ss,pp,ost = {},{},{}
			lastportid = 0

			if '@addr' in i['address']:
				address = i['address']['@addr']
			elif type(i['address']) is list:
				for ai in i['address']:
					if ai['@addrtype'] == 'ipv4':
						address = ai['@addr'] 

			addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

			if 'ports' in i and 'port' in i['ports']:
				if len(i['ports']['port']) >= 1:
					addnodes += "	addNode('addr"+addressmd5+"', '"+address+"', '\uf0a0', '#090', '#999'); \n"+\
									"	edges.add({ id: 'edge"+addressmd5+"', from: 'addr"+addressmd5+"', to: 'scan"+scanmd5+"', color:{color: '#cccccc'} }); \n"

				for pobj in i['ports']['port']:
					if type(pobj) is dict:
						p = pobj
					else:
						p = i['ports']['port']

					if lastportid == p['@portid']:
						continue
					else:
						lastportid = p['@portid']
	
					if addressmd5 not in portnodes:
						portnodes[addressmd5] = {}

					if p['@portid'] not in portnodes[addressmd5]:
						portnodes[addressmd5][p['@portid']] = {}
					
					if p['state']['@state'] == 'closed':
						portnodes[addressmd5][p['@portid']]['state'] = 'closed'
					#	addnodes += "	addNode('port"+addressmd5+p['@portid']+"', '"+p['@portid']+"', '\uf057', '#f00', '#999'); "+\
					#	"	edges.add({ id: 'edgeport"+addressmd5+p['@portid']+"', from: 'addr"+addressmd5+"', to: 'port"+addressmd5+p['@portid']+"', color:{color: '#cccccc'} }); "
					elif p['state']['@state'] == 'open':
						portnodes[addressmd5][p['@portid']]['state'] = 'open'
					#	addnodes += "	addNode('port"+addressmd5+p['@portid']+"', '"+p['@portid']+"', '\uf058', '#090', '#999'); "+\
					#	"	edges.add({ id: 'edgeport"+addressmd5+p['@portid']+"', from: 'addr"+addressmd5+"', to: 'port"+addressmd5+p['@portid']+"', color:{color: '#cccccc'} }); "
					elif p['state']['@state'] == 'filtered':
						portnodes[addressmd5][p['@portid']]['state'] = 'filtered'
					#	addnodes += "	addNode('port"+addressmd5+p['@portid']+"', '"+p['@portid']+"', '\uf146', '#666', '#999'); "+\
					#	"	edges.add({ id: 'edgeport"+addressmd5+p['@portid']+"', from: 'addr"+addressmd5+"', to: 'port"+addressmd5+p['@portid']+"', color:{color: '#cccccc'} }); "

					v,z,e = '','',''
          
					if 'service' in p:
						if '@version' in p['service']:
							portnodes[addressmd5][p['@portid']]['version'] = p['service']['@version']
						else:
							portnodes[addressmd5][p['@portid']]['version'] = 'No Version'

						if '@product' in p['service']:
							portnodes[addressmd5][p['@portid']]['product'] = p['service']['@product']
						else:
							portnodes[addressmd5][p['@portid']]['product'] = 'No Product'

						if '@extrainfo' in p['service']:
							portnodes[addressmd5][p['@portid']]['extrainfo'] = p['service']['@extrainfo']
						else:
							portnodes[addressmd5][p['@portid']]['extrainfo'] = ''

		# this fix single host report
		if type(ik) is not dict:
			break;


	r['js'] = '<script> $(document).ready(function() { '+\
	''+\
	'	var portnodes = '+json.dumps(portnodes)+';'+\
	"	addNode('scan"+scanmd5+"', '"+request.session['scanfile']+"', '\uf15b', '#ccc', '#ccc');"+\
	addnodes+\
	''+\
	'	function showPortNodes(addrmd5) { '+\
	'		for(i in portnodes[addrmd5]) { '+\
	'			if(portnodes[addrmd5][i]["state"] == "closed") {'+\
	'				addNode("port"+addrmd5+i, i, "\uf057", "#f00", "#999"); '+\
	'				edges.add({ id: "edgeport"+addrmd5+i, from: "addr"+addrmd5, to: "port"+addrmd5+i, color:{color: "#cccccc"} }); '+\
	'			}'+\
	'			if(portnodes[addrmd5][i]["state"] == "open") {'+\
	'				addNode("port"+addrmd5+i, i, "\uf058", "#090", "#999"); '+\
	'				edges.add({ id: "edgeport"+addrmd5+i, from: "addr"+addrmd5, to: "port"+addrmd5+i, color:{color: "#cccccc"} }); '+\
	'			}'+\
	'			if(portnodes[addrmd5][i]["state"] == "filtered") {'+\
	'				addNode("port"+addrmd5+i, i, "\uf146", "#666", "#999"); '+\
	'				edges.add({ id: "edgeport"+addrmd5+i, from: "addr"+addrmd5, to: "port"+addrmd5+i, color:{color: "#cccccc"} }); '+\
	'			}'+\
	'		}'+\
	'	} '+\
	''+\
	'	function showPortDetails(addrmd5, port) { '+\
	'		console.log(portnodes[addrmd5][port]["product"]); '+\
	'		addNode("product"+addrmd5+port, "\\n"+portnodes[addrmd5][port]["product"]+" / "+portnodes[addrmd5][port]["version"]+"\\n"+portnodes[addrmd5][port]["extrainfo"], "\uf27a", "#666", "#999"); '+\
	'		edges.add({ id: "edgeproduct"+addrmd5+port, from: "port"+addrmd5+port, to: "product"+addrmd5+port, color:{color: "#cccccc"} }); '+\
	'	} '+\
	''+\
	'	network.on("click", function (params) { '+\
	'		params.event = "[original event]"; '+\
	'		var pointer = this.getNodeAt(params.pointer.DOM); '+\
	'		if(/^addr(.+)$/.test(pointer)) { '+\
	'			var addrmd5obj = /^addr(.+)$/.exec(pointer); '+\
	'			console.log(addrmd5obj[1]);'+\
	'			showPortNodes(addrmd5obj[1]); '+\
	'		} '+\
	'		if(/^port(.+)$/.test(pointer)) { '+\
	'			var addrmd5obj = /^port([a-f0-9]{32,32})([0-9]+)$/.exec(pointer); '+\
	'			console.log(addrmd5obj[1]);'+\
	'			showPortDetails(addrmd5obj[1], addrmd5obj[2]); '+\
	'		} '+\
	'	}); '+\
	''+\
	' }); '+\
	' </script>'

	return render(request, 'nmapreport/nmap_network.html', r)
