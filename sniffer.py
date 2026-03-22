import multiprocessing
from datetime import datetime
from cachetools import LRUCache
from scapy.all import sniff, IP, TCP, UDP, DNS
from config import BPF_FILTER, sniffer_logger
from data_structures import PacketData


class PacketSniffer:
    def __init__(self):
        self.queue = multiprocessing.Queue(maxsize=15000)
        self.stop_event = multiprocessing.Event()
        self.process = None
        self.iface_to_use = None

    def set_config(self, iface_name: str, filter_str: str):
        self.iface_to_use = iface_name

    def start_sniffing(self):
        if self.process and self.process.is_alive(): return
        if not self.iface_to_use: return
        self.stop_event.clear()
        sniffer_logger.info(f"Сниффер запущен. iface={self.iface_to_use}")
        self.process = multiprocessing.Process(
            target=self._sniff_process_loop, args=(self.iface_to_use, self.queue, self.stop_event), daemon=True
        )
        self.process.start()

    def stop_sniffing(self):
        if self.process:
            self.stop_event.set()
            self.process.join(2.0)
            if self.process.is_alive(): self.process.terminate()

    def get_packets(self):
        p = []
        while not self.queue.empty():
            try:
                p.append(self.queue.get_nowait())
            except:
                break
        return p

    @staticmethod
    def _sniff_process_loop(iface, queue, stop_evt):
        dns_c = LRUCache(maxsize=5000)

        def cb(packet):
            try:
                if not packet.haslayer(IP): return
                ip = packet[IP]
                if packet.haslayer(DNS) and packet[DNS].qr == 1:
                    for i in range(packet[DNS].ancount):
                        r = packet[DNS].an[i]
                        if r.type == 1: dns_c[r.rdata] = r.rrname.decode('utf-8', 'ignore').strip('.')

                is_tcp, is_udp = packet.haslayer(TCP), packet.haslayer(UDP)
                dom = dns_c.get(ip.dst) or dns_c.get(ip.src)

                queue.put_nowait(PacketData(
                    timestamp=datetime.now(), src_ip=ip.src, dst_ip=ip.dst,
                    src_port=packet[TCP].sport if is_tcp else None,
                    dst_port=packet[TCP].dport if is_tcp else None,
                    length=len(packet), is_tcp=is_tcp, is_udp=is_udp,
                    tcp_flags={'SYN': 'S' in str(packet[TCP].flags)} if is_tcp else {},
                    protocol='TCP' if is_tcp else 'UDP', domain=dom
                ))
            except Exception as e:
                # Избавление от Except Pass 
                sniffer_logger.debug(f"Pkt err: {e}")

        try:
            sniff(iface=iface, store=0, prn=cb, stop_filter=lambda _: stop_evt.is_set())
        except Exception as se:
            sniffer_logger.critical(f"Sniff Critical: {se}")