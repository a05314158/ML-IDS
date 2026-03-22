from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list

print("Список интерфейсов Scapy:")
for iface in get_windows_if_list():
    print(f"Name: {iface['name']}, Desc: {iface['description']}")