import netifaces

netifaces.gateways()

interfaces = netifaces.interfaces()

for interface in interfaces:
	print(interface)

print(netifaces.ifaddresses(str(interfaces[0])))

addrs = netifaces.ifaddresses(str(interfaces[0]))
print(addrs[netifaces.AF_INET])
print(addrs[netifaces.AF_LINK])

