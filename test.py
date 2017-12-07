from packet import Packet

packet = Packet('192.168.31.48')
print(packet.sendCmd('get_prop', ['power']))