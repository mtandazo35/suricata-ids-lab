# -*- coding: utf-8 -*-
"""En la ficha de una publica: que CPE privado esta detras de lo que le denuncian.

Es el cruce que da sentido al resto: de "a mi IP publica le denuncian escaneo de puertos"
a "y el que escanea es el 192.168.4.77". Nadie mas puede hacerlo, porque hace falta ver el
trafico por dentro del NAT.

Lo que se protege:
  - que las categorias denunciadas decidan a quien se busca: DDoS y escaneo no llevan a
    los mismos CPEs;
  - que se busque en el nodo al que pertenece esa publica, no en todos;
  - que se presenten como CANDIDATOS: detras de una publica hay cientos de abonados y
    nada une una denuncia concreta con un CPE concreto;
  - y que las categorias lleguen en la forma que el cruce espera. En la ficha vienen como
    pares [categoria, cuantas] y el cruce quiere los identificadores: pasarle los pares no
    se veia como un error, la seccion simplemente desaparecia.
"""
import ast
import ipaddress
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("AIDB_SENAL", "senal_de_categorias", "culpables_por_senal", "culpables_de",
          "rid_de_publica", "culpables_ficha_html")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


# r1 tiene el rango de la publica que se mira; r2 es otro nodo con otros abonados
CPES = {
    "r1": [("r1|192.168.4.77", {"ip": "192.168.4.77", "riesgo": 70,
                                "puertos_top": {}, "cats_top": {"Escaneo de puertos": 300}}),
           ("r1|192.168.4.20", {"ip": "192.168.4.20", "riesgo": 60,
                                "puertos_top": {"25": 800}, "cats_top": {"Spam": 40}}),
           ("r1|192.168.4.99", {"ip": "192.168.4.99", "riesgo": 95,
                                "puertos_top": {"443": 9000}, "cats_top": {"Anomalia TCP": 4000}})],
    "r2": [("r2|10.9.9.9", {"ip": "10.9.9.9", "riesgo": 88,
                            "puertos_top": {}, "cats_top": {"Escaneo de puertos": 999}})],
}

PUBLICAS = {"r1": ["192.141.39.0/24"], "r2": ["203.0.113.0/24"]}


def entorno():
    ns = {"html": __import__("html"), "ipaddress": ipaddress,
          "cargar_publicas": lambda: PUBLICAS,
          "_cpes_del_nodo": lambda rid: CPES.get(rid, []),
          "cargar_enviados": lambda path=None: {},
          "MK_SENT": "", "MK_SENT_DNS": "",
          "ip_de": lambda k: k.split("|", 1)[-1]}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


ESCANEO = 14        # "Port Scan" en AbuseIPDB
SPAM = 11


def main():
    ns = entorno()

    # --- de que nodo es la publica -------------------------------------------------------
    check("una publica se atribuye a su nodo",
          ns["rid_de_publica"]("192.141.39.202") == "r1", ns["rid_de_publica"]("192.141.39.202"))
    check("y otra al suyo", ns["rid_de_publica"]("203.0.113.9") == "r2", "")
    check("una que no esta declarada no se atribuye a ninguno",
          ns["rid_de_publica"]("8.8.8.8") == "", ns["rid_de_publica"]("8.8.8.8"))
    check("lo que no es una IP no revienta", ns["rid_de_publica"]("vaya") == "")

    # --- el cruce ---------------------------------------------------------------------------
    h = ns["culpables_ficha_html"]("192.141.39.202", [[ESCANEO, 1]])
    check("con escaneo denunciado sale el CPE que escanea",
          "192.168.4.77" in h, h[:220])
    check("y no el que solo mueve mucho trafico normal", "192.168.4.99" not in h, "")
    check("se dice por que se le senala", "Escaneo de puertos" in h, "")

    h2 = ns["culpables_ficha_html"]("192.141.39.202", [[SPAM, 1]])
    check("con spam denunciado sale otro: el que saca correo",
          "192.168.4.20" in h2 and "192.168.4.77" not in h2, h2[:220])

    # --- el nodo importa -----------------------------------------------------------------------
    # Los abonados de un nodo no tienen nada que ver con los de otro: buscar en todos
    # senalaria a gente de otra red por un ataque que no hizo.
    check("no se senala a un CPE de otro nodo",
          "10.9.9.9" not in ns["culpables_ficha_html"]("192.141.39.202", [[ESCANEO, 1]]), "")

    # --- la forma de las categorias --------------------------------------------------------------
    # En la ficha vienen como pares; el cruce quiere los identificadores. Si no se
    # convierten, esto fallaba por dentro y la seccion desaparecia sin decir nada.
    check("acepta las categorias como pares, que es como llegan de la ficha",
          "192.168.4.77" in ns["culpables_ficha_html"]("192.141.39.202", [[ESCANEO, 3]]), "")
    check("y tambien sueltas, por si acaso",
          "192.168.4.77" in ns["culpables_ficha_html"]("192.141.39.202", [ESCANEO]), "")

    # --- honestidad ------------------------------------------------------------------------------
    check("se presentan como candidatos, no como culpables",
          "candidatos" in h and "culpable" not in h.lower(), "")
    check("y se pide confirmar antes de cortar", "antes de cortar" in h, "")
    check("se puede actuar desde ahi mismo", "/cuarentena/enviar" in h, "")

    # --- lo que no se sabe -------------------------------------------------------------------------
    check("sin categorias denunciadas no se inventa nada",
          ns["culpables_ficha_html"]("192.141.39.202", []) == "", "")
    vacio = ns["culpables_ficha_html"]("203.0.113.9", [[SPAM, 1]])
    check("si ningun CPE del nodo encaja se dice, en vez de dejar el hueco",
          "Ningun CPE" in vacio, vacio[:200])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
