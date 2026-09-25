# -*- coding: utf-8 -*-
"""Banco de regresion de deteccion: el generador y el comparador.

El banco en si necesita Suricata y se corre en el sensor (tests/pcap/run.sh). Lo que se
comprueba aqui, sin Suricata, es la maquinaria: que las capturas se generen validas y
deterministas, y que el comparador distinga un fallo de un aviso.

Esa distincion es la que decide si el banco sirve o estorba. Un caso BENIGNO que alerta
es un fallo nuestro: rompe clientes hoy y tiene que parar la suite. Un caso de ataque
que no se detecta puede ser que ET Open haya retirado la firma esta semana, y dejar el
repositorio en rojo por eso hace que la gente deje de mirar el rojo.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = os.path.join(RAIZ, "tests", "pcap")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def leer_pcap(ruta):
    """Devuelve (red, [paquetes]) validando la cabecera."""
    b = open(ruta, "rb").read()
    magic, vmaj, _vmin, _tz, _sig, snap, red = struct.unpack("<IHHiIII", b[:24])
    paq, i = [], 24
    while i + 16 <= len(b):
        _ts, _us, inc, orig = struct.unpack("<IIII", b[i:i + 16])
        if inc != orig or i + 16 + inc > len(b):
            raise ValueError("paquete truncado o longitudes que no cuadran")
        paq.append(b[i + 16:i + 16 + inc])
        i += 16 + inc
    return magic, vmaj, snap, red, paq


def comparar(esp, firmas, tmp):
    pe = os.path.join(tmp, "e.json")
    pv = os.path.join(tmp, "v.json")
    with open(pe, "w", encoding="utf-8") as f:
        json.dump(esp, f)
    with open(pv, "w", encoding="utf-8") as f:
        for s in firmas:
            f.write(json.dumps({"event_type": "alert", "alert": {"signature": s}}) + "\n")
    r = subprocess.run([sys.executable, os.path.join(PCAP, "comparar.py"), pe, pv],
                       capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def main():
    tmp = tempfile.mkdtemp()

    # --- el generador ------------------------------------------------------------------
    r = subprocess.run([sys.executable, os.path.join(PCAP, "generar.py")],
                       capture_output=True, text=True, cwd=PCAP)
    check("las capturas se generan", r.returncode == 0, r.stderr[-200:])

    casos = sorted(d for d in os.listdir(PCAP)
                   if os.path.isdir(os.path.join(PCAP, d)))
    check("hay casos benignos y de ataque",
          any(c.startswith("benigno") for c in casos)
          and any(c.startswith("escaneo") for c in casos), casos)

    for c in casos:
        cap = os.path.join(PCAP, c, "captura.pcap")
        esp = os.path.join(PCAP, c, "expected.json")
        check("%s: tiene captura y esperado" % c,
              os.path.exists(cap) and os.path.exists(esp))
        magic, vmaj, snap, red, paq = leer_pcap(cap)
        check("%s: el pcap es valido y es Ethernet" % c,
              magic == 0xA1B2C3D4 and vmaj == 2 and red == 1 and snap == 65535,
              (hex(magic), vmaj, red))
        check("%s: trae paquetes" % c, len(paq) > 0, len(paq))
        d = json.load(open(esp, encoding="utf-8"))
        check("%s: el esperado dice por que importa" % c,
              d.get("descripcion") and d.get("por_que_importa"), list(d))

    # --- determinismo: dos generaciones dan el mismo byte --------------------------------
    antes = open(os.path.join(PCAP, "benigno-dns", "captura.pcap"), "rb").read()
    subprocess.run([sys.executable, os.path.join(PCAP, "generar.py")],
                   capture_output=True, cwd=PCAP)
    despues = open(os.path.join(PCAP, "benigno-dns", "captura.pcap"), "rb").read()
    check("la captura es identica en cada generacion, o no sirve para comparar",
          antes == despues)

    # --- los benignos son los obligatorios -----------------------------------------------
    for c in casos:
        d = json.load(open(os.path.join(PCAP, c, "expected.json"), encoding="utf-8"))
        if c.startswith("benigno"):
            check("%s: es obligatorio y no admite ni una alerta" % c,
                  d.get("obligatorio") is True and d.get("max_alertas") == 0, d)
        else:
            check("%s: es informativo, no tumba la suite si ET retira la firma" % c,
                  d.get("obligatorio") is False, d)

    # --- el comparador ---------------------------------------------------------------
    check("un benigno limpio pasa", comparar({"max_alertas": 0}, [], tmp)[0] == 0)

    cod, txt = comparar({"max_alertas": 0}, ["ET INFO cosa rara"], tmp)
    check("un benigno que alerta es FALLA, no aviso", cod == 1 and txt.startswith("FALLA"), txt)
    check("y dice que firma fue, para poder excluirla", "ET INFO cosa rara" in txt, txt)

    cod, txt = comparar({"min_alertas": 1, "must_alert": ["scan"], "obligatorio": False},
                        [], tmp)
    check("un ataque no detectado es AVISO, no falla", cod == 1 and txt.startswith("AVISO"), txt)

    cod, _ = comparar({"min_alertas": 1, "must_alert": ["scan"], "obligatorio": False},
                      ["ET SCAN Potential SSH Scan"], tmp)
    check("con la firma esperada, pasa", cod == 0)

    cod, _ = comparar({"min_alertas": 1, "must_alert": ["telnet", "scan", "mirai"],
                       "obligatorio": False}, ["ET SCAN generico"], tmp)
    check("basta con que case UNA palabra: las firmas de ET cambian de nombre", cod == 0)

    cod, txt = comparar({"max_alertas": 5, "must_not_alert": ["spam"]},
                        ["ET SPAM correo"], tmp)
    check("lo que NO debe alertar tambien se comprueba",
          cod == 1 and "spam" in txt.lower(), txt)

    # Si Suricata no llego a arrancar no hay eve.json. Tratarlo como "ninguna alerta"
    # haria pasar en verde todos los benignos sin haber analizado nada: un banco que
    # aprueba cuando no se ejecuto es peor que no tenerlo.
    pe = os.path.join(tmp, "solo-esperado.json")
    with open(pe, "w", encoding="utf-8") as f:
        json.dump({"max_alertas": 0}, f)
    r = subprocess.run([sys.executable, os.path.join(PCAP, "comparar.py"), pe,
                        os.path.join(tmp, "no-existe.json")],
                       capture_output=True, text=True)
    check("un eve.json ausente es FALLA, no 'cero alertas'",
          r.returncode == 1 and "no hay eve.json" in r.stdout, r.stdout.strip())

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
