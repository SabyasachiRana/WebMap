from django.test import TestCase
import nmapreport.nmap.cve as cve
import os


cdir = os.path.dirname(os.path.realpath(__file__))


class CveTestCase(TestCase):
	def setUp(self):
		self.std_cpe = {
			'cpe': {
				'192.168.1.1': {
					'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
					'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82'
				},
				'192.168.1.53': {},
				'192.168.1.57': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:samba:samba:4': 'cpe:/a:samba:samba:4',
					'cpe:/a:redhat:cockpit': 'cpe:/a:redhat:cockpit'
				},
				'192.168.1.58': {
					'cpe:/a:apple:airtunes:377.40.00': 'cpe:/a:apple:airtunes:377.40.00'},
				'192.168.1.65': {},
				'192.168.1.70': {},
				'192.168.1.96': {},
				'192.168.1.99': {
					'cpe:/a:openbsd:openssh:9.8': 'cpe:/a:openbsd:openssh:9.8'},
				'192.168.1.122': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:igor_sysoev:nginx:1.21.5': 'cpe:/a:igor_sysoev:nginx:1.21.5'},
				'192.168.1.130': {
					'cpe:/a:vsftpd:vsftpd': 'cpe:/a:vsftpd:vsftpd',
					'cpe:/a:openbsd:openssh:6.0p1': 'cpe:/a:openbsd:openssh:6.0p1',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:apache:http_server': 'cpe:/a:apache:http_server',
					'cpe:/a:samba:samba': 'cpe:/a:samba:samba',
					'cpe:/a:plex:plex_media_server': 'cpe:/a:plex:plex_media_server'},
				'192.168.1.141': {},
				'192.168.1.64': {
					'cpe:/a:openbsd:openssh:9.2p1': 'cpe:/a:openbsd:openssh:9.2p1',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel'},
				'192.168.2.1': {},
				'192.168.2.100': {
					'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
					'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82'
				},
				'192.168.2.106': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.112': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65'},
				'192.168.2.225': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.227': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2'}
			},
			'cve': {
				'192.168.1.1': {},
				'192.168.1.53': {},
				'192.168.1.57': {},
				'192.168.1.58': {},
				'192.168.1.65': {},
				'192.168.1.70': {},
				'192.168.1.96': {},
				'192.168.1.99': {},
				'192.168.1.122': {},
				'192.168.1.130': {},
				'192.168.1.141': {},
				'192.168.1.64': {},
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {},
				'192.168.2.112': {},
				'192.168.2.225': {},
				'192.168.2.227': {}
			}}

		self.new_cpei_leg = {
			'cpe': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.112': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65'},
				'192.168.2.214': {},
				'192.168.2.225': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.227': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2'
				}
			},
			'cve': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {},
				'192.168.2.112': {},
				'192.168.2.214': {},
				'192.168.2.225': {},
				'192.168.2.227': {}
			}
		}

		self.new_cpe = {
			'cpe': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.112': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65'},
				'192.168.2.214': {},
				'192.168.2.225': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.227': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2'}},
			'cve': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {
					'CVE-2024-6387': 'CVE-2024-6387', 'CVE-2025-26465': 'CVE-2025-26465', 'CVE-2025-26466': 'CVE-2025-26466',
					'CVE-2025-32728': 'CVE-2025-32728', 'CVE-2025-61985': 'CVE-2025-61985', 'CVE-2025-61984': 'CVE-2025-61984',
					'CVE-2023-51767': 'CVE-2023-51767', 'CVE-2023-51385': 'CVE-2023-51385', 'CVE-2023-48795': 'CVE-2023-48795',
					'CVE-2023-38408': 'CVE-2023-38408', 'CVE-2023-28531': 'CVE-2023-28531', 'CVE-2019-16905': 'CVE-2019-16905',
					'CVE-2016-10009': 'CVE-2016-10009', 'CVE-2003-1562': 'CVE-2003-1562', 'CVE-2001-1585': 'CVE-2001-1585',
					'CVE-2001-1507': 'CVE-2001-1507', 'CVE-2001-1459': 'CVE-2001-1459', 'CVE-2001-1382': 'CVE-2001-1382',
					'CVE-2001-1380': 'CVE-2001-1380', 'CVE-2001-1029': 'CVE-2001-1029', 'CVE-2001-0872': 'CVE-2001-0872',
					'CVE-2001-0816': 'CVE-2001-0816', 'CVE-2001-0572': 'CVE-2001-0572', 'CVE-2001-0529': 'CVE-2001-0529',
					'CVE-2000-1169': 'CVE-2000-1169', 'CVE-2000-0999': 'CVE-2000-0999', 'CVE-2000-0992': 'CVE-2000-0992',
					'CVE-2000-0525': 'CVE-2000-0525', 'CVE-2000-0217': 'CVE-2000-0217', 'CVE-2000-0143': 'CVE-2000-0143',
					'CVE-2023-5178': 'CVE-2023-5178', 'CVE-2023-39191': 'CVE-2023-39191', 'CVE-2024-0562': 'CVE-2024-0562',
					'CVE-2023-4004': 'CVE-2023-4004', 'CVE-2023-6610': 'CVE-2023-6610', 'CVE-2023-6606': 'CVE-2023-6606',
					'CVE-2023-42753': 'CVE-2023-42753', 'CVE-2023-3640': 'CVE-2023-3640', 'CVE-2023-39192': 'CVE-2023-39192',
					'CVE-2023-33952': 'CVE-2023-33952', 'CVE-2023-33951': 'CVE-2023-33951', 'CVE-2023-6536': 'CVE-2023-6536',
					'CVE-2023-6535': 'CVE-2023-6535', 'CVE-2023-6356': 'CVE-2023-6356',
					'CVE-2023-6240': 'CVE-2023-6240', 'CVE-2023-42755': 'CVE-2023-42755', 'CVE-2023-5090': 'CVE-2023-5090',
					'CVE-2023-4273': 'CVE-2023-4273', 'CVE-2024-1151': 'CVE-2024-1151', 'CVE-2024-0443': 'CVE-2024-0443',
					'CVE-2023-4459': 'CVE-2023-4459', 'CVE-2023-4194': 'CVE-2023-4194', 'CVE-2023-4132': 'CVE-2023-4132',
					'CVE-2023-3773': 'CVE-2023-3773', 'CVE-2023-3772': 'CVE-2023-3772', 'CVE-2025-4598': 'CVE-2025-4598',
					'CVE-2023-4732': 'CVE-2023-4732', 'CVE-2024-0340': 'CVE-2024-0340', 'CVE-2021-33624': 'CVE-2021-33624',
					'CVE-2016-4117': 'CVE-2016-4117'},
				'192.168.2.112': {
					'CVE-2024-6387': 'CVE-2024-6387', 'CVE-2025-26465': 'CVE-2025-26465', 'CVE-2025-26466': 'CVE-2025-26466',
					'CVE-2025-32728': 'CVE-2025-32728', 'CVE-2025-61985': 'CVE-2025-61985', 'CVE-2025-61984': 'CVE-2025-61984',
					'CVE-2023-51767': 'CVE-2023-51767', 'CVE-2023-51385': 'CVE-2023-51385', 'CVE-2023-48795': 'CVE-2023-48795',
					'CVE-2023-38408': 'CVE-2023-38408', 'CVE-2023-28531': 'CVE-2023-28531', 'CVE-2019-16905': 'CVE-2019-16905',
					'CVE-2016-10009': 'CVE-2016-10009', 'CVE-2003-1562': 'CVE-2003-1562', 'CVE-2001-1585': 'CVE-2001-1585',
					'CVE-2001-1507': 'CVE-2001-1507', 'CVE-2001-1459': 'CVE-2001-1459', 'CVE-2001-1382': 'CVE-2001-1382',
					'CVE-2001-1380': 'CVE-2001-1380', 'CVE-2001-1029': 'CVE-2001-1029', 'CVE-2001-0872': 'CVE-2001-0872',
					'CVE-2001-0816': 'CVE-2001-0816', 'CVE-2001-0572': 'CVE-2001-0572', 'CVE-2001-0529': 'CVE-2001-0529',
					'CVE-2000-1169': 'CVE-2000-1169', 'CVE-2000-0999': 'CVE-2000-0999', 'CVE-2000-0992': 'CVE-2000-0992',
					'CVE-2000-0525': 'CVE-2000-0525', 'CVE-2000-0217': 'CVE-2000-0217', 'CVE-2000-0143': 'CVE-2000-0143',
					'CVE-2023-5178': 'CVE-2023-5178', 'CVE-2023-39191': 'CVE-2023-39191', 'CVE-2024-0562': 'CVE-2024-0562',
					'CVE-2023-4004': 'CVE-2023-4004', 'CVE-2023-6610': 'CVE-2023-6610', 'CVE-2023-6606': 'CVE-2023-6606',
					'CVE-2023-42753': 'CVE-2023-42753', 'CVE-2023-3640': 'CVE-2023-3640', 'CVE-2023-39192': 'CVE-2023-39192',
					'CVE-2023-33952': 'CVE-2023-33952', 'CVE-2023-33951': 'CVE-2023-33951', 'CVE-2023-6536': 'CVE-2023-6536',
					'CVE-2023-6535': 'CVE-2023-6535', 'CVE-2023-6356': 'CVE-2023-6356', 'CVE-2023-6240': 'CVE-2023-6240',
					'CVE-2023-42755': 'CVE-2023-42755', 'CVE-2023-5090': 'CVE-2023-5090', 'CVE-2023-4273': 'CVE-2023-4273',
					'CVE-2024-1151': 'CVE-2024-1151', 'CVE-2024-0443': 'CVE-2024-0443', 'CVE-2023-4459': 'CVE-2023-4459',
					'CVE-2023-4194': 'CVE-2023-4194', 'CVE-2023-4132': 'CVE-2023-4132', 'CVE-2023-3773': 'CVE-2023-3773',
					'CVE-2023-3772': 'CVE-2023-3772', 'CVE-2025-4598': 'CVE-2025-4598', 'CVE-2023-4732': 'CVE-2023-4732',
					'CVE-2024-0340': 'CVE-2024-0340', 'CVE-2021-33624': 'CVE-2021-33624', 'CVE-2016-4117': 'CVE-2016-4117'},
				'192.168.2.214': {},
				'192.168.2.225': {
					'CVE-2024-6387': 'CVE-2024-6387', 'CVE-2025-26465': 'CVE-2025-26465', 'CVE-2025-26466': 'CVE-2025-26466',
					'CVE-2025-32728': 'CVE-2025-32728', 'CVE-2025-61985': 'CVE-2025-61985', 'CVE-2025-61984': 'CVE-2025-61984',
					'CVE-2023-51767': 'CVE-2023-51767',
					'CVE-2023-51385': 'CVE-2023-51385', 'CVE-2023-48795': 'CVE-2023-48795', 'CVE-2023-38408': 'CVE-2023-38408',
					'CVE-2023-28531': 'CVE-2023-28531', 'CVE-2019-16905': 'CVE-2019-16905', 'CVE-2016-10009': 'CVE-2016-10009',
					'CVE-2003-1562': 'CVE-2003-1562', 'CVE-2001-1585': 'CVE-2001-1585', 'CVE-2001-1507': 'CVE-2001-1507',
					'CVE-2001-1459': 'CVE-2001-1459', 'CVE-2001-1382': 'CVE-2001-1382', 'CVE-2001-1380': 'CVE-2001-1380',
					'CVE-2001-1029': 'CVE-2001-1029', 'CVE-2001-0872': 'CVE-2001-0872', 'CVE-2001-0816': 'CVE-2001-0816',
					'CVE-2001-0572': 'CVE-2001-0572', 'CVE-2001-0529': 'CVE-2001-0529', 'CVE-2000-1169': 'CVE-2000-1169',
					'CVE-2000-0999': 'CVE-2000-0999', 'CVE-2000-0992': 'CVE-2000-0992', 'CVE-2000-0525': 'CVE-2000-0525',
					'CVE-2000-0217': 'CVE-2000-0217', 'CVE-2000-0143': 'CVE-2000-0143', 'CVE-2023-5178': 'CVE-2023-5178',
					'CVE-2023-39191': 'CVE-2023-39191', 'CVE-2024-0562': 'CVE-2024-0562', 'CVE-2023-4004': 'CVE-2023-4004',
					'CVE-2023-6610': 'CVE-2023-6610', 'CVE-2023-6606': 'CVE-2023-6606', 'CVE-2023-42753': 'CVE-2023-42753',
					'CVE-2023-3640': 'CVE-2023-3640', 'CVE-2023-39192': 'CVE-2023-39192', 'CVE-2023-33952': 'CVE-2023-33952',
					'CVE-2023-33951': 'CVE-2023-33951', 'CVE-2023-6536': 'CVE-2023-6536', 'CVE-2023-6535': 'CVE-2023-6535',
					'CVE-2023-6356': 'CVE-2023-6356', 'CVE-2023-6240': 'CVE-2023-6240', 'CVE-2023-42755': 'CVE-2023-42755',
					'CVE-2023-5090': 'CVE-2023-5090', 'CVE-2023-4273': 'CVE-2023-4273', 'CVE-2024-1151': 'CVE-2024-1151',
					'CVE-2024-0443': 'CVE-2024-0443', 'CVE-2023-4459': 'CVE-2023-4459', 'CVE-2023-4194': 'CVE-2023-4194',
					'CVE-2023-4132': 'CVE-2023-4132', 'CVE-2023-3773': 'CVE-2023-3773', 'CVE-2023-3772': 'CVE-2023-3772',
					'CVE-2025-4598': 'CVE-2025-4598', 'CVE-2023-4732': 'CVE-2023-4732', 'CVE-2024-0340': 'CVE-2024-0340',
					'CVE-2021-33624': 'CVE-2021-33624', 'CVE-2016-4117': 'CVE-2016-4117'},
				'192.168.2.227': {
					'CVE-2024-6387': 'CVE-2024-6387', 'CVE-2025-26465': 'CVE-2025-26465', 'CVE-2025-26466': 'CVE-2025-26466',
					'CVE-2025-32728': 'CVE-2025-32728', 'CVE-2025-61985': 'CVE-2025-61985', 'CVE-2025-61984': 'CVE-2025-61984',
					'CVE-2023-51767': 'CVE-2023-51767', 'CVE-2023-51385': 'CVE-2023-51385', 'CVE-2023-48795': 'CVE-2023-48795',
					'CVE-2023-38408': 'CVE-2023-38408', 'CVE-2023-28531': 'CVE-2023-28531', 'CVE-2019-16905': 'CVE-2019-16905',
					'CVE-2016-10009': 'CVE-2016-10009', 'CVE-2003-1562': 'CVE-2003-1562', 'CVE-2001-1585': 'CVE-2001-1585',
					'CVE-2001-1507': 'CVE-2001-1507', 'CVE-2001-1459': 'CVE-2001-1459', 'CVE-2001-1382': 'CVE-2001-1382',
					'CVE-2001-1380': 'CVE-2001-1380', 'CVE-2001-1029': 'CVE-2001-1029', 'CVE-2001-0872': 'CVE-2001-0872',
					'CVE-2001-0816': 'CVE-2001-0816', 'CVE-2001-0572': 'CVE-2001-0572', 'CVE-2001-0529': 'CVE-2001-0529',
					'CVE-2000-1169': 'CVE-2000-1169', 'CVE-2000-0999': 'CVE-2000-0999', 'CVE-2000-0992': 'CVE-2000-0992',
					'CVE-2000-0525': 'CVE-2000-0525', 'CVE-2000-0217': 'CVE-2000-0217', 'CVE-2000-0143': 'CVE-2000-0143',
					'CVE-2023-5178': 'CVE-2023-5178', 'CVE-2023-39191': 'CVE-2023-39191', 'CVE-2024-0562': 'CVE-2024-0562',
					'CVE-2023-4004': 'CVE-2023-4004', 'CVE-2023-6610': 'CVE-2023-6610', 'CVE-2023-6606': 'CVE-2023-6606',
					'CVE-2023-42753': 'CVE-2023-42753', 'CVE-2023-3640': 'CVE-2023-3640', 'CVE-2023-39192': 'CVE-2023-39192',
					'CVE-2023-33952': 'CVE-2023-33952', 'CVE-2023-33951': 'CVE-2023-33951', 'CVE-2023-6536': 'CVE-2023-6536',
					'CVE-2023-6535': 'CVE-2023-6535', 'CVE-2023-6356': 'CVE-2023-6356', 'CVE-2023-6240': 'CVE-2023-6240',
					'CVE-2023-42755': 'CVE-2023-42755', 'CVE-2023-5090': 'CVE-2023-5090', 'CVE-2023-4273': 'CVE-2023-4273',
					'CVE-2024-1151': 'CVE-2024-1151', 'CVE-2024-0443': 'CVE-2024-0443', 'CVE-2023-4459': 'CVE-2023-4459',
					'CVE-2023-4194': 'CVE-2023-4194', 'CVE-2023-4132': 'CVE-2023-4132', 'CVE-2023-3773': 'CVE-2023-3773',
					'CVE-2023-3772': 'CVE-2023-3772', 'CVE-2025-4598': 'CVE-2025-4598', 'CVE-2023-4732': 'CVE-2023-4732',
					'CVE-2024-0340': 'CVE-2024-0340', 'CVE-2021-33624': 'CVE-2021-33624', 'CVE-2016-4117': 'CVE-2016-4117'}}}

		self.tst_cpe_req_cpe = {
			'cpe': {
				'192.168.1.1': {
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2',
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82',
					'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65',
					'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
				},
			},
			'cve': {
				'192.168.1.1': {
				},
			}}

		self.tst_cpe_req_cve = {
			'cpe': {
				'192.168.1.1': {
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
				},
			},
			'cve': {
				'192.168.1.1': {
					'CVE-2024-6387': 'CVE-2024-6387',
				},
			}}

		self.tst_cve_empty_json = {'192.168.1.1': []}
		self.tst_cve_json_OrigId = '53f830b8-0a3f-465b-8143-3b8a9948e749'

	def test_cve_loadScan_std(self):
		cpe_cve_list = cve.loadScan(os.path.join(cdir, '.testfiles/std_cve.xml'))
		# print(cpe_cve_list)
		self.assertEqual(cpe_cve_list, self.std_cpe)

	def test_cve_loadScan_new(self):
		cpe_cve_list = cve.loadScan(os.path.join(cdir, '.testfiles/new_cve.xml'))
		# print('cpe_cve_list:',cpe_cve_list)
		self.assertEqual(cpe_cve_list, self.new_cpe)

	def test_cve_getCveOnline_empty_cve(self):
		cve_json = cve.getCveOnline(self. tst_cpe_req_cpe)
		# print('cve_json:',cve_json)
		self.assertEqual(cve_json, self.tst_cve_empty_json)

	def test_cve_getCveOnline_cve(self):
		cve_json = cve.getCveOnline(self.tst_cpe_req_cve)
		# print('cve_json:',cve_json)
		# print('first cve record:',cve_json[list(self.tst_cpe_req_cve['cve'].keys())[0]][0])
		self.assertEqual(cve_json[list(self.tst_cpe_req_cve['cve'].keys())[0]][0][0]['cveMetadata']['assignerOrgId'], self.tst_cve_json_OrigId)
