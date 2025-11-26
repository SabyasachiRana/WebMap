import os
import re
import json
import time
import shlex
import shutil
import subprocess


cdir = os.path.dirname(os.path.realpath(__file__))


def nsePath():
	return os.path.join(cdir, 'nse')


def gethours(f):
	return {
		'1h': 3600,
		'1d': 86400,
		'1w': 604800,
		'1m': 2592000
	}[f]


def genActiveScanFilePath(sched):
	return '/tmp/' + str(sched['number']) + '_' + sched['params']['filename'] + '.active'


def genFinishedScanFileName(sched):
	return 'webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename']


def genScanCmd(sched):
	return [shutil.which('nmap')] + shlex.split(sched['params']['params']) + ['--script=' + nsePath() + '/',
		'-oX', genActiveScanFilePath(sched), sched['params']['target']]


def runScan(sched):
	nmap_active_scan_out = genActiveScanFilePath(sched)
	nmapprocess = subprocess.Popen(genScanCmd(sched), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
	stdout, stderr = nmapprocess.communicate()
	print('[DONE] ' + stderr + stdout)
	return nmapprocess.returncode, nmap_active_scan_out, stderr, stdout


def cron():

	schedfiles = os.listdir('/opt/schedule/')

	nextsched = time.time() + gethours('1m')
	for i in schedfiles:
		if re.search(r'^[a-f0-9]{32,32}\.json$', i.strip()) is not None:
			try:
				sched = json.loads(open('/opt/schedule/' + i, "r").read())
			except ValueError as e:
				print("Error in json content of ", i, ': ', e)
				continue
			except IOError as e:
				print("Error while rading  ", i, ': ', e)
				continue

			nextrun = (sched['lastrun'] + gethours(sched['params']['frequency']))
			if nextrun <= time.time():
				sched['number'] = (sched['number'] + 1)
				print("[RUN]   scan:" + sched['params']['filename'] + " id:" + str(sched['number']) + " (nextrun:" + str(nextrun) + " / now:" + str(time.time()) + ")")

				# first make sure to write down current run
				sched['lastrun'] = time.time()
				f = open('/opt/schedule/' + i, "w")
				f.write(json.dumps(sched, indent=4))
				nextrun = sched['lastrun'] + gethours(sched['params']['frequency'])

				errorCode, nmap_active_scan_out, stdout, stderr = runScan(sched)
				print('[DONE] ' + stderr + stdout)
				if errorCode != 0:
					os.remove(nmap_active_scan_out)
				else:
					time.sleep(5)
					nmap_out_file = genFinishedScanFileName(sched)
					shutil.move(nmap_active_scan_out, '/opt/xml/' + nmap_out_file)
					nmapout = os.popen('python3 ' + cdir + '/cve.py webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename'] + '').readlines()
					print(nmapout)
				time.sleep(10)
			else:
				print("[SKIP]  scan:" + sched['params']['filename'] + " id:" + str(sched['number']) + " (nextrun:" + str(nextrun) + " / now:" + str(time.time()) + ")")
			nextsched = min(nextsched, nextrun)
		print("[DEBUG] nextsched:" + str(nextsched - time.time()))


if __name__ == '__main__':
	cron()
