import time, requests, json
from sniffer import PacketSniffer
from feature_engineer import extract_features

SERVER_URL = "http://172.20.77.37:5000/api/sensor_data"  # Твой IP
INTERFACE = "Беспроводная сеть"
SENSOR_SECRET = "security_token_999"


def run_sensor():
    sniffer = PacketSniffer()
    sniffer.set_config(INTERFACE, "ip or tcp or udp")
    sniffer.start_sniffing()
    print(f"[*] СЕНСОР АКТИВИРОВАН. Сбор реального веса трафика...")

    try:
        while True:
            time.sleep(2)
            packets = sniffer.get_packets()
            if packets:
                fv = extract_features(packets, time.time())

                # Считаем реальный объем байт в этой пачке
                total_payload_size = sum(p.length for p in packets)

                payload = {
                    "secret": SENSOR_SECRET,
                    "features": fv.features,
                    "packet_count": len(packets),
                    "total_bytes": total_payload_size  # НОВОЕ: реальные байты
                }

                try:
                    res = requests.post(SERVER_URL, json=payload, timeout=5)
                    print(
                        f"[+] Отправлено: {len(packets)} пкт / {total_payload_size} байт. ИИ: {res.json().get('status')}")
                except Exception as e:
                    print(f"[!] Ошибка связи: {e}")
            else:
                print("[.] Тишина в эфире...")
    except KeyboardInterrupt:
        sniffer.stop_sniffing()


if __name__ == "__main__":
    run_sensor()