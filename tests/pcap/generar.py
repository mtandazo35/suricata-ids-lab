#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Genera las capturas del banco de regresion, sin depender de trafico ajeno.

Por que sinteticas y no capturas reales:

  - una captura de trafico real de un ISP lleva datos de abonados dentro. No se puede
    meter en un repositorio publico ni mandar a nadie;
  - las capturas de terceros cambian de licencia, de sitio y de contenido;
  - y sobre todo: si la captura no es identica en cada ejecucion, el banco deja de
    servir para lo unico que tiene que servir, que es detectar que un cambio de reglas
    ha cambiado el resultado.

Aqui cada paquete se construye byte a byte y siempre igual, asi que dos ejecuciones
separadas por meses comparan lo mismo.

Uso:  python3 generar.py        (deja los .pcap junto a cada expected.json)
"""
import os
import struct
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"


def ip4(txt):
    return bytes(int(x) for x in txt.split("."))


def _suma(datos):
    if len(datos) % 2:
        datos += b"\x00"
    t = 0
    for i in range(0, len(datos), 2):
        t += (datos[i] << 8) + datos[i + 1]
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def ipv4(src, dst, proto, carga, ident=1):
    cab = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(carga), ident, 0x4000, 64, proto, 0)
    cab = cab + ip4(src) + ip4(dst)
    return cab[:10] + struct.pack("!H", _suma(cab)) + cab[12:] + carga


def udp(sp, dp, carga):
    return struct.pack("!HHHH", sp, dp, 8 + len(carga), 0) + carga


def tcp(sp, dp, seq, ack, flags, carga=b""):
    # offset 5 palabras, ventana fija; el checksum va en 0 y Suricata no lo exige
    # (el trafico espejado llega con checksums rotos por offload, y la config los ignora)
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 8192, 0, 0) + carga


def trama(src_mac, dst_mac, ip_paq):
    return dst_mac + src_mac + b"\x08\x00" + ip_paq


def escribir(ruta, paquetes):
    """Formato libpcap clasico, Ethernet."""
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(paquetes):
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def nombre_dns(host):
    out = b""
    for parte in host.split("."):
        out += bytes([len(parte)]) + parte.encode()
    return out + b"\x00"


def consulta_dns(host, ident=0x1234):
    cab = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return cab + nombre_dns(host) + struct.pack("!HH", 1, 1)


def respuesta_dns(host, ip, ident=0x1234):
    cab = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
    q = nombre_dns(host) + struct.pack("!HH", 1, 1)
    r = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip4(ip)
    return cab + q + r


# --------------------------------------------------------------------------- casos
def caso_dns_normal():
    """Navegacion corriente: consultas DNS a dominios de toda la vida."""
    paq = []
    for i, host in enumerate(["www.google.com", "graph.facebook.com", "www.whatsapp.com",
                              "api.spotify.com", "www.bing.com"]):
        paq.append(trama(MAC_A, MAC_B, ipv4("192.168.10.20", "8.8.8.8", 17,
                                            udp(40000 + i, 53, consulta_dns(host, 0x1000 + i)),
                                            ident=100 + i)))
        paq.append(trama(MAC_B, MAC_A, ipv4("8.8.8.8", "192.168.10.20", 17,
                                            udp(53, 40000 + i,
                                                respuesta_dns(host, "142.250.0.%d" % (i + 1),
                                                              0x1000 + i)),
                                            ident=200 + i)))
    return paq


def caso_https_normal():
    """Una sesion HTTPS normal: handshake TCP, algo de datos y cierre limpio."""
    paq = []
    sp, dst = 51000, "142.250.79.1"
    paq.append(trama(MAC_A, MAC_B, ipv4("192.168.10.20", dst, 6, tcp(sp, 443, 1000, 0, 0x02))))
    paq.append(trama(MAC_B, MAC_A, ipv4(dst, "192.168.10.20", 6, tcp(443, sp, 5000, 1001, 0x12))))
    paq.append(trama(MAC_A, MAC_B, ipv4("192.168.10.20", dst, 6, tcp(sp, 443, 1001, 5001, 0x10))))
    for i in range(6):
        paq.append(trama(MAC_A, MAC_B, ipv4("192.168.10.20", dst, 6,
                                            tcp(sp, 443, 1001 + i * 100, 5001, 0x18,
                                                b"\x17\x03\x03" + b"\x00" * 97))))
    paq.append(trama(MAC_A, MAC_B, ipv4("192.168.10.20", dst, 6, tcp(sp, 443, 2000, 5001, 0x11))))
    paq.append(trama(MAC_B, MAC_A, ipv4(dst, "192.168.10.20", 6, tcp(443, sp, 5001, 2001, 0x11))))
    return paq


def caso_ntp_normal():
    """Sincronizacion de hora: trafico UDP que a veces se confunde con amplificacion."""
    carga = b"\x1b" + b"\x00" * 47
    return [trama(MAC_A, MAC_B, ipv4("192.168.10.20", "162.159.200.1", 17,
                                     udp(41000, 123, carga), ident=300)),
            trama(MAC_B, MAC_A, ipv4("162.159.200.1", "192.168.10.20", 17,
                                     udp(123, 41000, b"\x24" + b"\x00" * 47), ident=301))]


def caso_escaneo_ssh():
    """Un CPE probando el puerto 22 en muchas direcciones distintas: patron de escaneo.

    Solo SYN, sin respuesta, que es justo como se ve un barrido."""
    paq = []
    for i in range(120):
        paq.append(trama(MAC_A, MAC_B,
                         ipv4("192.168.10.55", "203.0.113.%d" % (i % 254 + 1), 6,
                              tcp(40000 + i, 22, 7000 + i, 0, 0x02), ident=1000 + i)))
    return paq


def caso_escaneo_telnet():
    """El barrido clasico de las botnets de IoT: 23 y 2323 a media internet."""
    paq = []
    for i in range(120):
        pto = 23 if i % 2 == 0 else 2323
        paq.append(trama(MAC_A, MAC_B,
                         ipv4("192.168.10.56", "198.51.100.%d" % (i % 254 + 1), 6,
                              tcp(41000 + i, pto, 8000 + i, 0, 0x02), ident=2000 + i)))
    return paq


CASOS = {
    "benigno-dns": caso_dns_normal,
    "benigno-https": caso_https_normal,
    "benigno-ntp": caso_ntp_normal,
    "escaneo-ssh": caso_escaneo_ssh,
    "escaneo-telnet": caso_escaneo_telnet,
}


def main():
    for nombre, fn in sorted(CASOS.items()):
        d = os.path.join(AQUI, nombre)
        os.makedirs(d, exist_ok=True)
        ruta = os.path.join(d, "captura.pcap")
        paq = fn()
        escribir(ruta, paq)
        print("%-18s %3d paquetes  %6d bytes" % (nombre, len(paq), os.path.getsize(ruta)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
