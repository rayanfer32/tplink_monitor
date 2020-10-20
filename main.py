import argparse
# import curses
import os
import traceback
import time
import requests
import socket
import struct
import base64
from tabulate import tabulate
from operator import itemgetter


class Config(object):
	def __init__(self):
		self.mac_to_hostname = {}
		self.sleep_time = 1.0
		self.global_unit = 'kB'
		self.terminal_available = False
		self.curses_screen = None
		self.sort_key = StatKeys.BYTE_PER_SECOND_KEY
		self.running = True
		self.should_reset = False
		self.should_reset_hostnames = True
		self.summary_mode = True


class HostnameKeys(object):
	IP_ADDRESS_KEY = 'IPAddress'
	MAC_ADDRESS_KEY = 'MACAddress'
	HOST_NAME_KEY = 'hostName'


class StatKeys(object):
	IP_ADDRESS_KEY = 'ipAddress'
	MAC_ADDRESS_KEY = 'associatedDeviceMACAddress'
	TOTAL_BYTES_KEY = 'X_TP_TotalPacketsReceived'
	SENT_BYTES_KEY = 'X_TP_TotalPacketsSent'
	CURRENT_BYTES_KEY = 'currBytes'
	BYTE_PER_SECOND_KEY = 'bytesPerSec'
	'''
	Possible keys coming from modem are:
		'ipAddress',
		'macAddress',
		'totalPkts',
		'totalBytes',
		'currPkts',
		'currBytes',
		'currIcmp',
		'currUdp',
		'currSyn',
		'currIcmpMax',
		'currUdpMax',
		'currSynMax',

	 Self added keys:
		'bytesPerSec'
	'''

knownMacs = {'9C:C1:72:18:F0:88':'Huawei',
			'68:05:71:F9:27:19':'Samsung Duos',
			'D8:A3:15:0E:F8:1B':'Vivo 1',
			'08:7F:98:47:AD:3F':'Vivo 2',
			'BC:85:56:CD:26:4D':'Foxconn',
			'C0:48:E6:7A:0A:9A':'Samsung TV',
			'F0:79:59:AC:AB:AC':'Asus Old',
			'F0:67:28:6A:68:0D':'Oppo'
			}



class FakeCurses(object):
	def addstr(self, s):
		print(s)

	def refresh(self):
		pass

	def clear(self):
		os.system('clear')

	@classmethod
	def endwin(self):
		pass

	def nodelay(self, b=None):
		pass

	def getch(self, prompt=None):
		# return raw_input(prompt)
		return ''

	def getkey(self, prompt=None):
		# return raw_input(prompt)
		return ''

	def getstr(self, promp=None):
		return ''


def ip_to_decimal(ip):
	return struct.unpack('!L', socket.inet_aton(ip))[0]


def decimal_to_ip(n):
	return socket.inet_ntoa(struct.pack('!L', n))


def _ask_modem_something(modem_address, modem_password, data, api_path):
	if not modem_address.startswith('http'):
		modem_address = 'http://' + modem_address.strip('/')

	api_path = api_path.lstrip('/')

	# encode as username:password
	# pswd = base64.b64encode(f'{username}:{modem_password}'.encode())
	pswd = base64.b64encode(modem_password.encode('utf-8'))
	# print(pswd)
	cookies = {
		'Authorization': f'Basic {pswd.decode()}'
		# 'Authorization': 'Basic YWRtaW46YWRtaW4='
	}
	headers = {
		'Referer': '{}/'.format(modem_address)
	}

	r = requests.post('{}/{}'.format(modem_address, api_path), headers=headers, cookies=cookies, data=data)

	# print(r.content)
	return r.content



def get_modem_mac_names(modem_address, modem_password):
	data = '[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'

	result = _ask_modem_something(modem_address, modem_password, data, api_path='cgi?5&1')
	# print(result)
	return result


def update_modem_stats(modem_address, modem_password):
	data = '[ACT_WLAN_UPDATE_ASSOC#1,1,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
	result = _ask_modem_something(modem_address, modem_password, data, api_path='cgi?7')
	return result

def get_modem_stats(modem_address, modem_password):
	data = '[LAN_WLAN_ASSOC_DEV#0,0,0,0,0,0#1,1,0,0,0,0]0,4\r\nAssociatedDeviceMACAddress\r\nX_TP_TotalPacketsSent\r\nX_TP_TotalPacketsReceived\r\nX_TP_HostName\r\n'

	update_modem_stats(modem_address,modem_password)
	result = _ask_modem_something(modem_address, modem_password, data, api_path='cgi?6')

	return result


def reset_modem_stats(modem_address, modem_password):
	data = '[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\naction=1\r\n'

	result = _ask_modem_something(modem_address, modem_password, data, api_path='cgi?2')

	return result


def create_mac_to_hostname(modem_mac_names_str):
	break_split = modem_mac_names_str.decode().split('\n')
	current_mac = ''
	split_dict = {}
	for arg in break_split:
		try:
			key, value = arg.split('=')

		except:
			continue

		if key == HostnameKeys.MAC_ADDRESS_KEY:
			mac_addr = value
			if mac_addr != current_mac:
				current_mac = mac_addr

		if current_mac:
			if current_mac not in split_dict:
				split_dict[current_mac] = {}

			if key == HostnameKeys.HOST_NAME_KEY:
				split_dict[current_mac] = value

	# print(split_dict)
	return split_dict


def split_modem_stats(modem_stats):
	break_split = modem_stats.decode().split('\n')
	current_ip = 0
	split_dict = {}
	for arg in break_split:
		try:
			key, value = arg.split('=')
			# if value.isnumeric():
			#     import math
			#     print(key,'::',math.trunc(int(value)/(1024)),'MB')
			# else:
			#     print(key,'::',value)
			
			if key == StatKeys.MAC_ADDRESS_KEY:
				current_ip += 1
				# print(current_ip,key,value)
				split_dict[current_ip] = {key:value}
			else:
				split_dict[current_ip][key] = value
			# print(split_dict)
		except Exception as e:
			# print(e)
			continue
		
	# print(split_dict)
	return split_dict


def display_current_stats(current_stats, unit=None):
	curses_screen = configs.curses_screen


	curses_screen.clear()
	for device in current_stats:
		prod = current_stats[device]
		# print(current_stats[device])
		for param in prod:
			# print(param,v)
			# print(type(param))
			import math
			try:
				if param == "X_TP_HostName":
					pass
				elif param == StatKeys.SENT_BYTES_KEY:
					packetSize = 1285
					print('%.2f MB'%(int(prod[param])*packetSize/(1024*1024)))
				elif param == StatKeys.MAC_ADDRESS_KEY:
					macid  = prod[param]
					if macid in knownMacs:
						print(f'{knownMacs[macid]}',end=" ~ ")
					else:
						print(f'{prod[param]}',end=" ~ ")
				elif param == StatKeys.BYTE_PER_SECOND_KEY:
					print(f'{prod[param]} KBps')
			except:
				pass
		# print('\n')
	# convert_values = {'B': 1, 'kB': float(1)/float(1024),
	#                   'b': 8, 'kb': float(1)/float(1024) * 8,
	#                   'mb': float(1)/float(1024**2) * 8, 'mB': float(1)/float(1024**2)}

	# if not unit:
	#     unit = configs.global_unit

	# if unit not in convert_values:
	#     unit = 'kB'

	# convert_value = convert_values.get(unit)

	# if configs.summary_mode is True:
	#     header_arr = ['IP', "Name", 'Cur({}ps)'.format(unit), 'Tot({})'.format(unit)]
	# else:
	#     header_arr = ['IP', 'MAC', "Name", 'Current ({}ps)'.format(unit), 'Total ({})'.format(unit)]

	# tab_array = []
	# for machine_stat in current_stats:
	#     arr = [machine_stat[0][StatKeys.MAC_ADDRESS_KEY]]
	#     if configs.summary_mode is True:
	#         del arr[1]
	#         name_field = arr[1]
	#         if len(name_field) > 9:
	#             arr[1] = name_field[0:9]

	#     tab_array.append(arr)

	# curses_screen.addstr(tabulate(tab_array, headers=header_arr, tablefmt="psql"))
	# if configs.summary_mode is True:
	#     help_str = '\n\n(m)Toggle MAC: '
	# else:
	#     help_str = '\n\n(q)Quit (t,c,i)Sort Total,Current,IP (r)Reset Totals (h)Reset Hostnames (m)Toggle MAC (u)Change Unit: '

	# curses_screen.addstr(help_str)
	curses_screen.refresh()

	curses_screen.nodelay(True)
	# try:
	#     char = curses_screen.getkey()
	#     if char in ['c', 'C']:
	#         configs.sort_key = StatKeys.BYTE_PER_SECOND_KEY
	#     elif char in ['t', 'T']:
	#         configs.sort_key = StatKeys.TOTAL_BYTES_KEY
	#     elif char in ['m', 'M']:
	#         configs.summary_mode = not configs.summary_mode
	#     elif char in ['u', 'U']:
	#         curses_screen.nodelay(False)
	#         curses_screen.addstr('\n\nEnter unit: ')
	#         curses_screen.refresh()
	#         string = curses_screen.getstr()
	#         configs.global_unit = string
	#     elif char in ['q', 'Q']:
	#         configs.running = False
	#     elif char in ['r', 'R']:
	#         curses_screen.nodelay(False)
	#         curses_screen.addstr('\n\nAre you sure you want to reset data? (y/n): ')
	#         curses_screen.refresh()
	#         inner_char = curses_screen.getkey()
	#         if inner_char in ['y', 'Y']:
	#             configs.should_reset = True
	#     elif char in ['h', 'H']:
	#         configs.should_reset_hostnames = True
	#     elif char in ['i', 'I']:
	#         configs.sort_key = StatKeys.IP_ADDRESS_KEY
	# except:
	#     pass


def run_indefinitely(modem_address, modem_password):
	last_run_dict = {}
	while configs.running:
		if configs.should_reset is True:
			reset_modem_stats(modem_address, modem_password)
			configs.should_reset = False
			last_run_dict = {}

		if configs.should_reset_hostnames is True:
			configs.mac_to_hostname = create_mac_to_hostname(get_modem_mac_names(ip_addr, modem_password))
			configs.should_reset_hostnames = False
		# print(modem_address)
		modem_stats = get_modem_stats(modem_address, modem_password)
		# print(modem_stats.decode().split('\n'))
		per_ip_modem_stats = split_modem_stats(modem_stats)
		# print(per_ip_modem_stats)

		for ip in per_ip_modem_stats:
			try:
				
				last_total_bytes = float(last_run_dict[ip].get(StatKeys.TOTAL_BYTES_KEY))
				last_total_bytes += float(last_run_dict[ip].get(StatKeys.SENT_BYTES_KEY))
				last_total_bytes = last_total_bytes/2
				current_total_bytes = float(per_ip_modem_stats[ip].get(StatKeys.TOTAL_BYTES_KEY))
				current_total_bytes += float(per_ip_modem_stats[ip].get(StatKeys.SENT_BYTES_KEY))
				current_total_bytes = current_total_bytes/2
				per_second = float(current_total_bytes - last_total_bytes) / float(configs.sleep_time)
				per_ip_modem_stats[ip][StatKeys.BYTE_PER_SECOND_KEY] = per_second#round(per_second, 2)
			except Exception as e:
				pass
				# print("ERROR:",e)

		# for ip, ip_stats in list(per_ip_modem_stats.items()):
		#     if ip in last_run_dict:
		
		# sorted_list = sorted(list(per_ip_modem_stats.values()), key=itemgetter(configs.sort_key), reverse=True)
		display_current_stats(per_ip_modem_stats)
		last_run_dict = dict(per_ip_modem_stats)
		time.sleep(configs.sleep_time)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()

	parser.add_argument('-a', action='store', dest='ip_addr', help='Modem address (Optional, defaults to: 192.168.0.1)', default='192.168.0.1',
						required=False)
	parser.add_argument('-u', action='store', dest='unit', help='Unit: b, B, kb, kB, mb, mB (Optional, defaults to: kB)', default='kB',
						required=False)
	parser.add_argument('-s', action='store', dest='sleep_time', help='Sleep time between each request in float seconds (Optional, defaults to: 1, minimum: 0.5)',
						default=1, required=False, type=float)
	parser.add_argument('-p', action='store', dest='password', help='Modem password (Mandatory)', default=False,
						required=True)
	parser.add_argument('--reset', action='store_true', dest='reset', help='Reset usage data (equivalent to using the reset button in statistics menu of web interface)', default=False,
						required=False)
	parser.add_argument('--summary', action='store_true', dest='summary', help='Open Sherry in summary mode (No MAC column)', default=False, required=False)

	results = parser.parse_args()

	ip_addr = results.ip_addr

	global configs
	configs = Config()

	configs.sleep_time = results.sleep_time
	# if configs.sleep_time < 0.5:
		# raise Exception('sleep_time can not be less than 0.5')

	configs.global_unit = results.unit
	if results.summary is True:
		configs.summary_mode = True

	if os.environ.get("TERM"):
		stdscr = curses.initscr()
	else:
		print('\n##################\nRunning in no Terminal mode...\n###################\n')
		time.sleep(1)
		stdscr = FakeCurses()
		curses = FakeCurses

	configs.curses_screen = stdscr
	configs.should_reset = results.reset

	try:
		run_indefinitely(ip_addr, results.password)
	except KeyboardInterrupt:
		pass
	except Exception as exc:
		traceback.print_exc()
	finally:
		curses.endwin()
