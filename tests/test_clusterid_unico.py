# -*- coding: utf-8 -*-
"""Cada interfaz de espejo tiene que llevar SU cluster-id.

El cluster-id de af-packet identifica un grupo de fanout del kernel. Dos interfaces
distintas con el mismo numero piden entrar al mismo grupo y el kernel rechaza la
segunda con "failed to set fanout mode: Invalid argument". Esa interfaz no arranca y
se lleva por delante el arranque entero de Suricata.

Paso de verdad en un sensor con dos MikroTik (2026-09-24): entraron 5 GB por ids-mon
y Suricata leyo 0 bytes, reiniciandose en bucle. Con un solo router no se ve nunca,
porque el choque solo aparece cuando -m trae varios origenes.
"""
import os
import re
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def purgador():
    """El trozo REAL que quita de af-packet los espejos que ya no existen."""
    ini = SRC.index("# --- PURGA:")
    fin = SRC.index("# PURGA-FIN", ini)
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", SRC[ini:fin], re.S)
    assert m, "no encontre la purga de espejos en el instalador"
    return m.group(1)


def renumerador():
    """El trozo REAL del instalador, no una copia: si alguien lo cambia, esto lo corre."""
    ini = SRC.index("# --- CLUSTERID:")
    fin = SRC.index("# CLUSTERID-FIN", ini)
    region = SRC[ini:fin]
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", region, re.S)
    assert m, "no encontre el renumerado de cluster-id en el instalador"
    return m.group(1)


def yaml_con(pares):
    """Un af-packet de juguete: [(interfaz, cluster-id), ...]."""
    out = ["af-packet:"]
    for iface, cid in pares:
        out += ["  - interface: %s" % iface,
                "    cluster-id: %d" % cid,
                "    cluster-type: cluster_flow"]
    out += ["  - interface: default", "    cluster-id: 99", ""]
    return "\n".join(out)


def correr(texto):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "suricata.yaml")
    with open(p, "w", encoding="utf-8") as f:
        f.write(texto)
    subprocess.run([sys.executable, "-c", renumerador(), p], check=True,
                   stdout=subprocess.DEVNULL)
    return open(p, encoding="utf-8").read()


def ids(texto):
    """cluster-id de cada interfaz, en orden."""
    out, actual = {}, None
    for l in texto.split("\n"):
        m = re.match(r"\s*-\s*interface:\s*(\S+)", l)
        if m:
            actual = m.group(1)
            continue
        m = re.match(r"\s*cluster-id:\s*(\d+)", l)
        if m and actual:
            out.setdefault(actual, int(m.group(1)))
    return out


def main():
    # --- el caso que rompio el sensor: dos espejos con el mismo numero ---
    r = ids(correr(yaml_con([("ids-mon", 98), ("ids-mon2", 98)])))
    check("dos interfaces de espejo NO comparten cluster-id",
          r.get("ids-mon") != r.get("ids-mon2"), r)
    check("la primera conserva el 98 de siempre", r.get("ids-mon") == 98, r)
    check("y la segunda recibe el siguiente", r.get("ids-mon2") == 99, r)

    # --- tres, por si manana hay tres MikroTik ---
    r = ids(correr(yaml_con([("ids-mon", 98), ("ids-mon2", 98), ("ids-mon3", 98)])))
    check("con tres espejos los tres numeros son distintos",
          len({r["ids-mon"], r["ids-mon2"], r["ids-mon3"]}) == 3, r)

    # --- no toca lo que no es suyo ---
    r = ids(correr(yaml_con([("ids-mon", 98)])))
    check("la interfaz 'default' se queda como estaba", r.get("default") == 99, r)
    check("un solo espejo sigue en 98: las cajas ya instaladas no cambian",
          r.get("ids-mon") == 98, r)

    # --- idempotente: correrlo dos veces no reasigna nada ---
    uno = correr(yaml_con([("ids-mon", 98), ("ids-mon2", 98)]))
    check("pasarlo dos veces deja el mismo resultado", ids(correr(uno)) == ids(uno))

    # --- purga: un espejo que ya no existe no puede quedarse en el yaml ---------
    # Si -m baja de dos origenes a uno, tzsp-decap deja de crear esa veth. Con el
    # bloque huerfano Suricata no arranca y la caja se queda sin analizar NADA,
    # mientras el espejo bueno sigue entrando: parece viva y esta ciega.
    d = tempfile.mkdtemp()
    ruta = os.path.join(d, 'suricata.yaml')
    def purgar(vivos, contenido=None):
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write(contenido or yaml_con([('ids-mon', 98), ('ids-mon2', 99)]))
        subprocess.run([sys.executable, '-c', purgador(), ruta, vivos], check=True,
                       stdout=subprocess.DEVNULL)
        return open(ruta, encoding='utf-8').read()

    txt = purgar('ids-mon')
    check('el espejo que ya no existe sale del yaml', 'ids-mon2' not in txt, txt)
    check('el que sigue vivo se queda', '- interface: ids-mon\n' in txt, txt)
    check('la interfaz default no se toca', '- interface: default' in txt, txt)
    check('se lleva las propiedades del bloque, no solo la cabecera',
          txt.count('cluster-type') == 1, txt)

    antes = yaml_con([('ids-mon', 98), ('ids-mon2', 99)])
    check('si los dos siguen vivos no se toca nada',
          purgar('ids-mon ids-mon2', antes) == antes)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
