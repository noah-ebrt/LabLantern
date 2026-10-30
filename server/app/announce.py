"""Kündigt den Master per mDNS im LAN an (_vulnwatch._tcp), damit `vulnwatch-agent setup` ihn findet.

Läuft als eigener Container im Host-Netz, ohne Daten, ohne Schlüssel, ohne Rechte. Eine gefälschte Ankündigung
im LAN hilft einem Angreifer nicht: Beim Pairing vergleicht der Admin einen Code aus Zertifikat und Geheimnis
des Agenten, der bei einem falschen Master nicht passt.
"""
import logging
import os
import signal
import socket
import threading

from zeroconf import ServiceInfo, Zeroconf

SERVICE = "_vulnwatch._tcp.local."


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ip = os.environ["VULNWATCH_BIND_IP"]
    port = int(os.environ.get("VULNWATCH_PORT", "8443"))
    info = ServiceInfo(SERVICE, f"vulnwatch.{SERVICE}", addresses=[socket.inet_aton(ip)], port=port,
                       properties={"v": "1"}, server="vulnwatch-master.local.")
    zc = Zeroconf(interfaces=[ip])
    zc.register_service(info)
    logging.info("Announcing vulnwatch at %s:%d via mDNS", ip, port)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    zc.unregister_service(info)
    zc.close()


if __name__ == "__main__":
    main()
