# -*- coding: utf-8 -*-
"""es_mi_cpe(): solo las IPs de TUS redes pueden ir a la cuarentena de CPEs.

Nace de un caso real: 97 IPs publicas golpeando un host interno aparecian como
"CPE origen (quien ataca)", y nada impedia que el motor las tratara como abonados
infectados (ET Open trae firmas ENTRANTES con la palabra "compromised", que este
panel cuenta como infeccion). Con politicas automaticas, podian acabar en la
address-list del MikroTik."""
import ast, os, sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()


def heredoc(nombre):
    i = SRC.index("cat > /usr/local/bin/%s <<'" % nombre)
    marca = SRC[i:].split("<<'", 1)[1].split("'", 1)[0]
    return SRC[i:].split("\n", 1)[1].split("\n" + marca + "\n", 1)[0]


def cargar(nombre, conf):
    """Ejecuta el bloque de redes propias de ese script con la config dada."""
    cuerpo = heredoc(nombre)
    arbol = ast.parse(cuerpo)
    ns = {"_ipm": __import__("ipaddress"), "ipaddress": __import__("ipaddress"),
          "_conf_key": lambda k, d: conf.get(k, d),
          "conf": lambda: conf}
    trozos = []
    for n in arbol.body:
        seg = ast.get_source_segment(cuerpo, n) or ""
        if ("_MIS_NETS" in seg or "def es_mi_cpe" in seg or "def mis_redes" in seg):
            trozos.append(seg)
    if not trozos:
        raise SystemExit("no se encontro el bloque de redes propias en " + nombre)
    exec("\n".join(trozos), ns)
    return ns["es_mi_cpe"]


fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1


for script in ("suricata-html-report", "suricata-dashboard"):
    print("--- %s ---" % script)
    es_mio = cargar(script, {})

    # por defecto: privadas + CGNAT
    for ip in ("10.0.0.67", "10.6.4.61", "172.19.1.3", "192.168.1.10", "100.64.0.5"):
        check("%s se reconoce como abonado tuyo" % ip, es_mio(ip) is True)

    # las del caso real: atacantes de internet
    for ip in ("85.217.140.23", "46.151.182.191", "64.62.197.138", "213.209.159.21",
               "94.154.43.163", "8.8.8.8"):
        check("%s NO puede entrar a la cuarentena de CPEs" % ip, es_mio(ip) is False)

    check("una IP mal formada no se toma por abonado", es_mio("no-es-ip") is False)
    check("vacio tampoco", es_mio("") is False)

    # configurable: un ISP que da IP publica a sus clientes
    es_mio2 = cargar(script, {"MIS_REDES": "203.0.113.0/24, 10.0.0.0/8"})
    check("con MIS_REDES, un cliente con IP publica SI cuenta", es_mio2("203.0.113.9") is True)
    check("y lo de fuera de esas redes sigue sin contar", es_mio2("85.217.140.23") is False)
    check("MIS_REDES reemplaza el valor por defecto (192.168 ya no entra)",
          es_mio2("192.168.1.10") is False)
    print()

print("TODO OK" if not fallos else "%d fallo(s)" % fallos)
raise SystemExit(1 if fallos else 0)
