import xmltodict
import json
import hashlib
import re
import sys
import requests


def getcpe(xmlfilename):
	return loadScan('/opt/xml/' + xmlfilename)


def loadScan(xmlpath):
	oo = xmltodict.parse(open(xmlpath, 'r').read())
	o = json.loads(json.dumps(oo['nmaprun'], indent=4))
	return cpeFromDict(o)


def cpeFromDict(o):
	cpe, cve = {}, {}
	# if we didn't find any host, we are done
	if 'host' not in o:
		res = {'cpe': cpe, 'cve': cve}
		return res

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		lastportid = 0

		if '@addr' in i['address']:
			address = i['address']['@addr']
			# print('address: ', address)
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					address = ai['@addr']
					# print('address: ', ai['@addr'])

		# addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()
		cpe[address] = {}
		cve[address] = {}

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

				if 'service' in p:
					if 'cpe' in p['service']:
						if type(p['service']['cpe']) is list:
							for cpei in p['service']['cpe']:
								cpe[address][cpei] = cpei
								# print('cpe: ',address,cpei)
						else:
							cpe[address][p['service']['cpe']] = p['service']['cpe']
							# print('cpe: ',address,p['service']['cpe'])

				if 'script' in p:
					# print('script: ',p['script'])
					if type(p['script']) is list:
						# print("1 ",p['script'])
						for scripti in p['script']:
							# print("2 ",scripti)
							if 'elem' in scripti:
								if type(scripti['elem']) is list:
									for elmi in scripti['elem']:
										if elmi['@key'] == 'cve':
											cve[address][elmi['#text']] = elmi['#text']
											# print('cve1: ',address,elmi['#text'])
					else:
						if 'table' in p['script'] and type(p['script']['table']) is list:
							# print("4 ",p['script']['table'])
							for tabi in p['script']['table']:
								# print('tabi: ',tabi)
								if 'table' in tabi and type(tabi['table']) is list:
									for tabii in tabi['table']:
										# print('tabii: ',tabii)
										if 'elem' in tabii and type(tabii['elem']) is list:
											for elmi in tabii['elem']:
												# print('elmi:: ',elmi)
												if elmi['@key'] == 'id':
													cve[address][elmi['#text']] = elmi['#text']
													# print('cve2: ',address,elmi['#text'])

		# this fix single host report
		if type(ik) is not dict:
			break

	res = {'cpe': cpe, 'cve': cve}
	return res


def getCveOnline(cpecve):
	cvejson = {}

	for i in cpecve['cpe']:
		# cprint(i)

		if i not in cvejson:
			cvejson[i] = []

		for cpestr in cpecve['cpe'][i]:
			print('cpe: ', cpestr)
			if re.search('^cpe:[^:]+:[^:]+:[^:]+:.+$', cpestr):
				r = requests.get('http://cve.circl.lu/api/cvefor/' + cpestr)
				print('http: ', r.status_code)
				if r.status_code == 200 and r.json() is not None:
					print('r: ', r.text)
					if r.json() is dict:
						cvejson[i].append(r.json())
					else:
						cvejson[i].append([r.json()])

	for i in cpecve['cve']:
		# print(i)

		if i not in cvejson:
			cvejson[i] = []

		for cvestr in cpecve['cve'][i]:
			# print('cve: ',cvestr)
			r = requests.get('http://cve.circl.lu/api/cve/' + cvestr)
			# print('http: ', r.status_code)
			if r.status_code == 200 and r.json() is not None:
				# print('r: ', r.text)
				if r.json() is dict:
					cvejson[i].append(r.json())
				else:
					cvejson[i].append([r.json()])
	return cvejson


def getcve(xmlfile):
	scanfilemd5 = hashlib.md5(str(xmlfile).encode('utf-8')).hexdigest()
	cpecve = getcpe(xmlfile)
	cvejson = getCveOnline(cpecve)
	for i in cvejson:
		hostmd5 = hashlib.md5(str(i).encode('utf-8')).hexdigest()
		# for cvei in cvejson[i]:
		# print(cvei)
		# continue

		if type(cvejson[i]) is list and len(cvejson[i]) > 0:
			f = open('/opt/notes/' + scanfilemd5 + '_' + hostmd5 + '.cve', 'w')
			f.write(json.dumps(cvejson[i], indent=4))
			f.close()


if __name__ == '__main__':
	getcve(sys.argv[1])
