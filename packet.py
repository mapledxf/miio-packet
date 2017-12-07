import subprocess
import json
import datetime
import calendar
import base64
import socket
import hashlib

class Packet:
	magic = '2131'
	unknown = '00000000'
	port = 54321
	timeout = 3

	def __init__(self, ip: str):
		self.ip = ip
		self.token = None
		self.device_type = None
		self.serial = None
		self._id = 2

		hellobytes = bytes.fromhex(Packet.magic + '0020' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
		hellohex = self.send(hellobytes)

		if(hellohex is None):
			print("Error: failed to get hello response")
			return

		if(not self.checkPacket(hellohex, True)):
			print("Error: failed to parse hello packet")
			return
			
		print("Got hello response: %s" % hellohex)
		self.device_type = hellohex[16:20]
		self.serial = hellohex[20:24]
		time = int(hellohex[24:32],16)
		self.time_diff = calendar.timegm(datetime.datetime.now().timetuple()) - time
		self.token = hellohex[32:64]
		self.key = self.md5(bytes.fromhex(self.token))
		self.iv = self.md5(self.key + bytes.fromhex(self.token))

	def send(self, msg:bytes) -> str:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		s.settimeout(Packet.timeout)
		try:
			s.sendto(msg, (self.ip, Packet.port))
			data, addr = s.recvfrom(1024)
			return data.hex()
		except Exception as ex:
			print(ex)
			return None

	def sendCmd(self, command: str, parameters = None) -> str:
		cmd = {"id": self._id, "method": command, }
		if parameters is not None:
			cmd["params"] = parameters
		msg = self.encodeMsg(cmd)
		if(msg is None):
			return

		response = self.send(msg)

		if(response is None):
			print("Error: failed to get response")
			return None

		print("Got response: %s" % response)

		return self.decodeMsg(response)

	def checkPacket(self, ciphertext: str, isHello: bool) -> bool:
		print('checkPacket %s' % ciphertext)
		if((not ciphertext.startswith(Packet.magic)) or len(ciphertext) < 64):
			print("Error: not a miio packet")
			return False
#		length = int(ciphertext[4:8], 16)
#
#		if(isHello):
#			length += 32
#		else:
#			length += 64
#
#		if(not len(ciphertext) == length):
#			print("Error: length not match: %s but %s found" % (length, len(ciphertext)))
#			return False
#
		if(isHello):
			return True

		checksum = self.md5(bytes.fromhex(ciphertext[0:32] + self.token + ciphertext[64:len(ciphertext)])).hex()
		if(not checksum == ciphertext[32:64]):
			print("Error: checksum not match")
			return False
		return True
	def md5(self, data: bytes) -> bytes:
		checksum = hashlib.md5()
		checksum.update(data)
		return checksum.digest()

	def encodeMsg(self, command: dict) -> bytes:
		if(self.token is None):
			print("Error: token is None")
			return None

		shell = 'echo \'' + json.dumps(command) + '\' |  openssl enc -aes-128-cbc -K ' + self.key.hex() + ' -iv ' + self.iv.hex() + ' -nosalt | hexdump -ve \'/1 "%02x"\''
		encrypt = bytes.fromhex(subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE).stdout.read().decode('utf-8'))
		length = format(len(encrypt) + 32, 'x').zfill(4)
		time = calendar.timegm(datetime.datetime.now().timetuple()) - self.time_diff
		server_time = format(time, 'x').zfill(8)
		zwraw = Packet.magic + length + Packet.unknown + self.device_type + self.serial + server_time + self.token + encrypt.hex()
		checksum = self.md5(bytes.fromhex(zwraw)).hex()
		result = Packet.magic + length + Packet.unknown + self.device_type + self.serial + server_time + checksum + encrypt.hex()
		return bytes.fromhex(result)

	def decodeMsg(self, ciphertext: str) -> str:
		if(not self.checkPacket(ciphertext, False)):
			print("Error: failed to decode packet %s " % ciphertext)
			return None

		base64_cipher = base64.b64encode(bytes.fromhex(ciphertext[64:len(ciphertext)])).decode("utf-8") 
		shell = 'echo ' + base64_cipher + ' |  openssl enc -aes-128-cbc -d -K ' + self.key.hex() + ' -iv ' + self.iv.hex() + ' -base64'
		decrypt = subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE).stdout.read().decode('utf-8')
		result = json.loads(decrypt)
		return result['result']


