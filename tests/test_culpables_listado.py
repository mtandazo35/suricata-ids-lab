# -*- coding: utf-8 -*-
"""De "me listaron" a "mira a estos abonados".

El listado dice el TIPO de abuso y el sensor sabe que CPEs lo estan haciendo. Cruzarlo es
la unica pista util que existe, porque hace falta ver el trafico por dentro y eso solo lo
tiene quien opera la red.

Lo que se protege:
  - que una lista de SPAM mande a buscar correo saliente, y la XBL a buscar un equipo
    tomado: son cosas distintas dentro de tu red y confundirlas hace perder el dia;
  - que la DROP NO senale a ningun abonado. Dice que la red esta secuestrada: va por
    asignacion y BGP, y buscar un CPE ahi es buscar donde no esta;
  - que la PBL no dispare nada, que en residencial es lo normal;
  - y que se presenten como CANDIDATOS. Con NAT hay cientos de abonados detras de una
    publica y nada une un listado concreto con un CPE concreto: decir "el culpable" seria
    mentir, y encima a alguien a quien se le va a cortar el internet.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("DNSBL_SENAL", "_DNSBL_SIN_CULPABLE", "senal_de_listas",
          "culpables_por_senal", "culpables_lista_html")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


CPES = [
    ("r1|192.168.1.10", {"ip": "192.168.1.10", "riesgo": 80,
                         "puertos_top": {"25": 900}, "cats_top": {"Spam": 40}}),
    ("r1|192.168.1.20", {"ip": "192.168.1.20", "riesgo": 70,
                         "puertos_top": {"3128": 200}, "cats_top": {"Botnet CnC": 12}}),
    ("r1|192.168.1.30", {"ip": "192.168.1.30", "riesgo": 90,
                         "puertos_top": {"443": 5000}, "cats_top": {"Anomalia TCP": 900}}),
]


def entorno():
    ns = {"html": __import__("html"),
          "_cpes_del_nodo": lambda rid: CPES,
          "cargar_enviados": lambda path=None: {},
          "MK_SENT": "", "MK_SENT_DNS": "",
          "ip_de": lambda k: k.split("|", 1)[-1]}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def bl(*pares, **kw):
    d = {"n_listadas": kw.get("n", 1),
         "ips": {ip: {"listas": list(ls), "solo_pbl": kw.get("pbl", False)}
                 for ip, ls in pares}}
    return d


def main():
    ns = entorno()
    senal = ns["senal_de_listas"]

    # --- el codigo del listado decide que se busca --------------------------------------
    pt, fr, mot, infra = senal(bl(("203.0.113.1", ["SpamCop"])))
    check("una lista de spam manda a buscar correo saliente", "25" in pt, pt)
    check("y lo dice con palabras", "correo saliente" in " ".join(mot), mot)
    check("no manda a buscar botnet", "Botnet CnC" not in fr, fr)

    pt, fr, mot, infra = senal(bl(("203.0.113.1", ["Spamhaus ZEN - XBL: equipo infectado"])))
    check("la XBL manda a buscar un equipo tomado", "Botnet CnC" in fr, fr)
    check("y puertos de proxy abierto", "3128" in pt, pt)
    check("no manda a buscar correo", "25" not in pt, pt)

    pt, fr, mot, _i = senal(bl(("203.0.113.1", ["Spamhaus ZEN - XBL: equipo infectado",
                                                "Barracuda"])))
    check("con las dos cosas se buscan las dos", "25" in pt and "3128" in pt, pt)

    # --- lo que NO senala a nadie -----------------------------------------------------------
    pt, fr, mot, infra = senal(bl(("203.0.113.1", ["Spamhaus ZEN - DROP: red secuestrada"])))
    check("la DROP no genera busqueda de abonados", not pt and not fr, (pt, fr))
    check("y se marca como problema de infraestructura", infra is True, infra)

    pt, fr, _m, infra = senal(bl(("203.0.113.1", ["Spamhaus ZEN - PBL: rango dinamico"]),
                                 pbl=True))
    check("la PBL en residencial no dispara nada", not pt and not fr and not infra,
          (pt, fr, infra))
    check("sin listas tampoco", senal({})[0] == set(), senal({}))

    # --- a quien se senala -------------------------------------------------------------------
    h = ns["culpables_lista_html"]("r1", bl(("203.0.113.1", ["SpamCop"])))
    check("con un listado de spam sale el CPE que saca correo",
          "192.168.1.10" in h, h[:200])
    check("y NO el que solo hace mucho trafico normal", "192.168.1.30" not in h, "")
    check("se dice por que se le senala", "900 alertas por 25" in h or "Spam" in h, "")
    check("se presentan como candidatos, no como culpables",
          "candidatos" in h and "culpable" not in h.lower(), "")
    check("y se pide confirmar antes de cortar", "antes de cortar" in h, "")

    h2 = ns["culpables_lista_html"]("r1", bl(("203.0.113.1",
                                              ["Spamhaus ZEN - XBL: equipo infectado"])))
    check("con la XBL sale el del proxy, no el del correo",
          "192.168.1.20" in h2 and "192.168.1.10" not in h2, h2[:220])

    # --- la DROP en pantalla ------------------------------------------------------------------
    h3 = ns["culpables_lista_html"]("r1", bl(("203.0.113.1",
                                              ["Spamhaus ZEN - DROP: red secuestrada"])))
    check("con DROP se explica que no hay CPE que buscar",
          "no es" in h3 and "192.168.1." not in h3, h3[:200])

    # --- cuando no encaja nadie -----------------------------------------------------------------
    ns["_cpes_del_nodo"] = lambda rid: []
    h4 = ns["culpables_lista_html"]("r1", bl(("203.0.113.1", ["SpamCop"])))
    check("si ningun CPE encaja se dice, en vez de dejar el hueco",
          "ningun CPE" in h4, h4[:200])
    check("y se apunta a donde puede estar", "otro nodo" in h4, h4[:220])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
