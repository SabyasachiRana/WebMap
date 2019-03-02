from django.shortcuts import render
from django.http import HttpResponse
import xmltodict, json, html, os, hashlib, re, urllib.parse, base64
from collections import OrderedDict
from nmapreport.functions import *

def ndiff(request, f1, f2):
	f = {}

	if token_check(request.GET['token']) is not True:
		return HttpResponse(json.dumps({'error':'invalid token'}, indent=4), content_type="application/json")

	f['f1'] = get_ports_details(f1)
	f['f2'] = get_ports_details(f2)

	r = get_diff(f['f1'],f['f2'])

	return HttpResponse(json.dumps(r, indent=4), content_type="application/json")

def check_cve_id(cveid, cveobj):
	for f1cvei in cveobj:
		for cvei in f1cvei:
			if cveid == cvei['id']:
				return True

	return False

def get_diff(f1,f2):
	r = {'hosts':{}, 'ports':{}, 'cve':{}}

	# ports f1 > f2
	for host in f1['hosts']:
		if host in f2['hosts']:
			r['hosts'][host] = '='
		else:
			r['hosts'][host] = '>'

		for i in f1['hosts'][host]['ports']:
			if host not in r['ports']:
				r['ports'][host] = {}
			if i['port'] not in r['ports'][host]:
				# r['ports'][host][i['port']] = {}

				r['ports'][host][i['port']] = {
					'port': '>',
					'name': '>',
					'state': '>',
					'product': '>',
					'extrainfo': '>',
					'diff': {}
				}

			if host in f2['hosts']:
				for f2p in f2['hosts'][host]['ports']:
					if i['port'] == f2p['port']:
						r['ports'][host][i['port']]['port'] = '='
						if i['name'] == f2p['name']:
							r['ports'][host][i['port']]['name'] = '='
						if i['state'] == f2p['state']:
							r['ports'][host][i['port']]['state'] = '='
						if i['product'] == f2p['product']:
							r['ports'][host][i['port']]['product'] = '='
						if i['extrainfo'] == f2p['extrainfo']:
							r['ports'][host][i['port']]['extrainfo'] = '='

			r['ports'][host][i['port']]['diff']['f1'] = i

	# ports f1 < f2
	for host in f2['hosts']:
		if host in f1['hosts']:
			r['hosts'][host] = '='
		else:
			r['hosts'][host] = '<'

		for i in f2['hosts'][host]['ports']:
			if host not in r['ports']:
				r['ports'][host] = {}
			if i['port'] not in r['ports'][host]:
				#r['ports'][host][i['port']] = {}

				r['ports'][host][i['port']] = {
					'port': '<',
					'name': '<',
					'state': '<',
					'product': '<',
					'extrainfo': '<',
					'diff': {}
				}

			if host in f1['hosts']:
				for f1p in f1['hosts'][host]['ports']:
					if i['port'] == f1p['port']:
						r['ports'][host][i['port']]['port'] = '='
						if i['name'] == f1p['name']:
							r['ports'][host][i['port']]['name'] = '='
						if i['state'] == f1p['state']:
							r['ports'][host][i['port']]['state'] = '='
						if i['product'] == f1p['product']:
							r['ports'][host][i['port']]['product'] = '='
						if i['extrainfo'] == f1p['extrainfo']:
							r['ports'][host][i['port']]['extrainfo'] = '='

			r['ports'][host][i['port']]['diff']['f2'] = i



	for host in f1['hosts']:
		if host not in r['cve']:
			r['cve'][host] = {}
		for f1cvei in f1['hosts'][host]['CVE']:
			for cvei in f1cvei:
				if host in f2['hosts']:
					if check_cve_id(cvei['id'], f2['hosts'][host]['CVE']) is not False:
						r['cve'][host][cvei['id']] = '='
					else:
						r['cve'][host][cvei['id']] = '>'

	for host in f2['hosts']:
		if host not in r['cve']:
			r['cve'][host] = {}
		for f2cvei in f2['hosts'][host]['CVE']:
			for cvei in f2cvei:
				if host in f1['hosts']:
					if check_cve_id(cvei['id'], f1['hosts'][host]['CVE']) is not False:
						r['cve'][host][cvei['id']] = '='
					else:
						r['cve'][host][cvei['id']] = '<'

	return r
