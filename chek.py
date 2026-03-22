from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list

print("Доступные интерфейсы на Windows:")
for iface in get_windows_if_list():
    print(f"Name: {iface['name']}, Description: {iface['description']}")