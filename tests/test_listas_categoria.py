# -*- coding: utf-8 -*-
"""Una address-list por categoria de abuso, no un unico cajon.

Meter en la misma lista al que tiene una botnet y al que usa BitTorrent obliga a darles
el mismo trato en el firewall, y no es el mismo problema: la botnet se corta, el P2P se
encola, el DNS se redirige al resolutor propio.

Lo que se protege aqui es la clasificacion. Si un CPE cae en la lista equivocada, o se
corta a quien no habia que cortar, o se deja suelto a quien si.
"""
import ast
import json
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("CAT_CPE", "CAT_OTROS", "_CPES_CACHE", "_cpes_de_reporte",
          "lista_de_categoria", "nombre_categoria", "categoria_cpe", "listas_cpe_reglas",
          "_TRAD", "traducir", "AIDB_SENAL", "senal_de_categorias", "listas_en_uso",
          "ros_lista", "_RE_ROS_RARO")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp, globales=None, enviados=None):
    ns = {"json": json, "os": os, "time": __import__("time"), "re": __import__("re"),
          "LOGDIR": tmp, "MK_SENT": "",
          "cargar_enviados": lambda path=None: dict(enviados or {}),
          "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip,
          "_mk_globales": lambda: dict(globales or {})}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def secciones(texto):
    """Agrupa las lineas generadas por la ruta de MikroTik en la que caen.

    Hace falta porque un mismo 'add' significa cosas distintas segun donde este: una
    marca de paquete bajo /ip firewall mangle es una marca, y bajo /queue tree es quien
    la consume. Comprobar el texto entero de corrido no distingue una cosa de la otra."""
    sec = {}
    actual = ""
    for ln in texto.split("\n"):
        ln = ln.strip()
        if ln.startswith("/"):
            actual = ln
            sec.setdefault(actual, [])
        elif ln and not ln.startswith("#") and actual:
            sec[actual].append(ln)
    return sec


REPORTE = {"candidatos": [], "dns_candidatos": [], "top_riesgo": [
    {"ip": "10.0.0.1", "router": "", "cats_top": {"Botnet CnC": 90, "BitTorrent / P2P": 900}},
    {"ip": "10.0.0.2", "router": "", "cats_top": {"BitTorrent / P2P": 5000}},
    {"ip": "10.0.0.3", "router": "", "cats_top": {"DNS sospechoso": 40}},
    {"ip": "10.0.0.4", "router": "", "cats_top": {"Escaneo SSH": 700}},
    {"ip": "10.0.0.5", "router": "", "cats_top": {"Spam": 1200}},
    {"ip": "10.0.0.6", "router": "", "cats_top": {"Criptomineria": 30}},
    {"ip": "10.0.0.7", "router": "", "cats_top": {"Fuerza bruta": 200}},
    {"ip": "10.0.0.8", "router": "", "cats_top": {"Anomalia TLS/SSL": 400}},
]}


def main():
    tmp = tempfile.mkdtemp()
    json.dump(REPORTE, open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))
    ns = entorno(tmp)

    # --- cada CPE a su categoria ---
    casos = [("10.0.0.2", "p2p"), ("10.0.0.3", "dns"), ("10.0.0.4", "escaneo"),
             ("10.0.0.5", "spam"), ("10.0.0.6", "minado"), ("10.0.0.7", "fuerza"),
             ("10.0.0.8", "otros")]
    for ip, esperada in casos:
        check("%s -> %s" % (ip, esperada), ns["categoria_cpe"](ip) == esperada,
              ns["categoria_cpe"](ip))

    # el caso que decide el diseño: uno que hace las dos cosas
    check("quien tiene botnet Y P2P es un CPE con BOTNET, no un CPE de P2P",
          ns["categoria_cpe"]("10.0.0.1") == "botnet", ns["categoria_cpe"]("10.0.0.1"))
    check("aunque el P2P tenga diez veces mas alertas", True)

    check("un CPE que no esta en el reporte cae en 'otros'",
          ns["categoria_cpe"]("10.9.9.9") == "otros")

    # --- nombres de lista ---
    check("la botnet va a clientes-botnet",
          ns["lista_de_categoria"]("botnet") == "clientes-botnet", ns["lista_de_categoria"]("botnet"))
    check("el DNS de malware a clientes-dns-malware",
          ns["lista_de_categoria"]("dns") == "clientes-dns-malware")
    check("el P2P a clientes-p2p", ns["lista_de_categoria"]("p2p") == "clientes-p2p")
    check("una categoria desconocida cae en la de otros",
          ns["lista_de_categoria"]("inventada") == "clientes-otros")

    # se pueden renombrar, por si el ISP ya tiene su nomenclatura
    ns2 = entorno(tmp, globales={"LISTA_BOTNET": "abusivos-botnet"})
    check("el nombre se puede cambiar desde la configuracion",
          ns2["lista_de_categoria"]("botnet") == "abusivos-botnet",
          ns2["lista_de_categoria"]("botnet"))
    check("y las que no se cambian siguen con el suyo",
          ns2["lista_de_categoria"]("p2p") == "clientes-p2p")

    # --- las reglas: cada lista con SU trato ---
    reg = ns["listas_cpe_reglas"]()
    check("la botnet se corta entera",
          "src-address-list=clientes-botnet action=drop" in reg, reg[:200])
    check("al de spam solo se le cierra el correo, no internet",
          "clientes-spam" in reg and "dst-port=25,465,587" in reg
          and "src-address-list=clientes-spam action=drop" not in reg, "")
    check("el DNS de malware se redirige al resolutor propio, no se corta",
          "clientes-dns-malware" in reg and "action=redirect" in reg
          and "src-address-list=clientes-dns-malware action=drop" not in reg, "")
    check("el P2P se encola, no se corta",
          "clientes-p2p" in reg
          and "src-address-list=clientes-p2p action=drop" not in reg, "")

    # --- encolar de verdad: marca de conexion -> marca de paquete -> cola que la consume ---
    # Que aparezca la palabra "queue" no limita nada. Una /queue simple con target=""
    # no engancha trafico y una marca de paquete que ninguna cola consume no la usa
    # nadie: el operador copia las reglas, el router las acepta sin chistar y se queda
    # creyendo que acoto el P2P. Aqui se comprueba la cadena ENTERA.
    sec = secciones(reg)
    mangle = sec.get("/ip firewall mangle", [])
    arbol = sec.get("/queue tree", [])

    def cadena(lista, con, pkt):
        """Los tres eslabones, cada uno en la seccion que le toca."""
        m_con = [r for r in mangle if "src-address-list=" + lista in r
                 and "action=mark-connection" in r and "new-connection-mark=" + con in r]
        m_pkt = [r for r in mangle if "connection-mark=" + con in r
                 and "action=mark-packet" in r and "new-packet-mark=" + pkt in r]
        cola = [r for r in arbol if "packet-mark=" + pkt in r and "max-limit=" in r]
        return m_con, m_pkt, cola

    for cat, lista, con, pkt in (("P2P", "clientes-p2p", "p2p-con", "p2p"),
                                 ("minado", "clientes-minado", "minado-con", "minado")):
        m_con, m_pkt, cola = cadena(lista, con, pkt)
        check("%s: la lista marca la CONEXION (%s)" % (cat, con), len(m_con) == 1, m_con)
        check("%s: esa conexion marca el PAQUETE (%s)" % (cat, pkt), len(m_pkt) == 1, m_pkt)
        check("%s: y una /queue tree consume esa marca con un limite" % cat,
              len(cola) == 1, cola)

    # el eslabon que faltaba: sin cola que consuma la marca, el limite no existe
    marcas_en_colas = set()
    for r in arbol:
        for t in r.split():
            if t.startswith("packet-mark="):
                marcas_en_colas.add(t.split("=", 1)[1])
    marcas_puestas = set()
    for r in mangle:
        for t in r.split():
            if t.startswith("new-packet-mark="):
                marcas_puestas.add(t.split("=", 1)[1])
    check("ninguna marca de paquete se queda sin cola que la consuma",
          marcas_puestas and marcas_puestas <= marcas_en_colas,
          sorted(marcas_puestas - marcas_en_colas))

    # minado no es P2P: comparten cola y el uno se come el limite del otro
    check("minado tiene su propia marca, no reutiliza la del P2P",
          "new-connection-mark=minado-con" in reg and "new-packet-mark=minado" in reg
          and not [r for r in mangle if "clientes-minado" in r and "p2p" in r], "")
    colas_p2p = [r for r in arbol if "packet-mark=p2p" in r]
    colas_min = [r for r in arbol if "packet-mark=minado" in r]
    check("y su propia cola, distinta de la del P2P",
          len(colas_p2p) == 1 and len(colas_min) == 1 and colas_p2p[0] != colas_min[0],
          (colas_p2p, colas_min))
    check("el minado no queda sin reglas propias aunque tenga lista",
          "clientes-minado" in reg, "")

    # lo que habia antes y no limitaba nada
    reglas = [r for v in sec.values() for r in v]   # solo ordenes, sin comentarios
    vacias = [r for r in reglas if 'target=""' in r]
    check("nada de /queue simple con target vacio, que no engancha trafico",
          not sec.get("/queue simple") and not vacias, (sec.get("/queue simple"), vacias))
    check("ni marcar el paquete directo desde la address-list, sin marca de conexion",
          not [r for r in mangle if "src-address-list=" in r and "action=mark-packet" in r], "")

    # --- los tres avisos operativos, sin los cuales las reglas parecen no funcionar ---
    coms = "\n".join(l for l in reg.split("\n") if l.strip().startswith("#")).lower()
    check("avisa que los drop van antes de fasttrack-connection",
          "fasttrack" in coms and "antes" in coms, "")
    check("avisa que la lista no corta las conexiones ya abiertas",
          "firewall connection remove" in coms, "")
    check("avisa que redirect usa el resolutor del propio router",
          "allow-remote-requests" in coms and "dst-nat" in coms, "")

    # =====================================================================================
    # Una categoria que nadie puede producir es una categoria MUERTA
    # =====================================================================================
    # Paso de verdad: CAT_CPE agrupaba por "Spam" y traducir() no producia ese nombre
    # jamas. Nada fallaba. Simplemente la categoria 'spam' no se le asignaba a nadie, la
    # address-list clientes-spam estaba siempre vacia, y la regla que el panel propone para
    # cortar el 25/465/587 no bloqueaba a nadie — siendo el correo saliente la causa numero
    # uno de que un ISP acabe en Spamhaus. Un fallo mudo de los caros.
    producibles = {t for _c, t in ns["_TRAD"]}
    muertas = []
    for c, nom, cats, lista in ns["CAT_CPE"]:
        falta = [x for x in cats if x not in producibles]
        if falta:
            muertas.append((c, falta, lista))
    check("toda categoria de CPE se puede asignar de verdad", not muertas, muertas)

    # lo mismo para la atribucion: busca nombres de categoria, y uno que no exista no
    # encuentra nunca a nadie sin decir por que
    busca = set()
    for d in ns["AIDB_SENAL"].values():
        busca |= set(d.get("cats") or [])
    check("y la atribucion no busca nombres que no existen",
          not (busca - producibles), sorted(busca - producibles))

    # las firmas reales de correo saliente tienen que caer en Spam...
    for fir in ("ET POLICY Outbound Spam", "ET POLICY SMTP Outbound Connection",
                "SMTP Open Relay detected"):
        check("'%s' se clasifica como Spam" % fir[:34],
              ns["traducir"](fir) == "Spam", ns["traducir"](fir))
    # ...sin robarle las suyas a las categorias vecinas, que es el riesgo de meter una
    # palabra tan generica en la tabla
    check("un brute force de SMTP sigue siendo fuerza bruta",
          ns["traducir"]("ET SCAN SMTP Login Brute Force") == "Fuerza bruta",
          ns["traducir"]("ET SCAN SMTP Login Brute Force"))
    check("y Spamhaus sigue siendo mala reputacion, no spam",
          ns["traducir"]("ET DROP Spamhaus DROP Listed") == "Mala reputacion",
          ns["traducir"]("ET DROP Spamhaus DROP Listed"))

    # =====================================================================================
    # Lo que se promete en pantalla es lo que se usa al enviar
    # =====================================================================================
    # La seccion decia "-> lista suricata-dns-sospechoso" y el envio iba a
    # clientes-dns-malware. El operador leia una lista y el sistema usaba otra, y eso pasaba
    # en la pantalla donde se decide dejar sin internet a un abonado.
    check("la fila dice a que lista va ESE CPE, no la de la seccion",
          "lista_de_categoria(categoria_cpe(k))" in DASH, "")
    check("y el modal de confirmacion nombra esa misma lista",
          "entra en la lista {esc(_lst)}" in DASH, "")
    check("la seccion ya no promete una lista unica",
          "address-list de <b>su categoria</b>" in DASH, "")

    # =====================================================================================
    # Las listas se pueden ver: cuales son y quien esta dentro
    # =====================================================================================
    ns3 = entorno(tmp, enviados={
        "10.0.0.1": {"lista": "clientes-botnet"},
        "10.0.0.2": {"lista": "clientes-botnet"},
        "10.0.0.3": {"lista": "clientes-p2p"},
        "10.0.0.4": {},                      # sin lista guardada
    })
    uso = {l: n for _c, _nom, l, n in ns3["listas_en_uso"]()}
    check("se cuenta cuantos CPEs hay en cada lista",
          uso.get("clientes-botnet") == 2 and uso.get("clientes-p2p") == 1, uso)
    check("las vacias salen igual, para saber que existen",
          uso.get("clientes-spam") == 0, uso)
    # el registro guarda la lista con la que se mando cada uno; uno sin ella no se puede
    # colocar en ninguna sin adivinar, y adivinar aqui seria decir que esta cortado donde
    # no lo esta
    check("un enviado sin lista guardada no se cuela en ninguna",
          sum(uso.values()) == 3, uso)
    check("estan las siete categorias mas otros",
          len(ns3["listas_en_uso"]()) == 8, len(ns3["listas_en_uso"]()))

    # listas_cpe_reglas() generaba todo esto y no lo llamaba nadie: codigo muerto
    check("el panel ensena las listas y sus reglas",
          "listas_cpe_reglas()" in DASH and "Las listas del MikroTik" in DASH, "")
    check("y avisa de que sin regla el panel dice enviado y no pasa nada",
          "dice <b>enviado</b> y no pasa nada" in DASH, "")

    # =====================================================================================
    # El diagnostico vigila las listas que se USAN
    # =====================================================================================
    # Antes miraba LIST y LIST_GRAD y nunca las clientes-*: avisaba de listas que no se
    # usan y callaba sobre las que si. "La lista de cuarentena NO corta nada" podia estar
    # en verde y aun asi no cortarse nada.
    check("el diagnostico incluye las listas de categoria en uso",
          "listas_en_uso() if n]" in DASH, "")
    # y solo las que tienen a alguien: una instalacion recien montada no puede salir con
    # siete avisos de listas vacias que nadie ha usado todavia
    check("pero solo las que tienen a alguien dentro",
          "for _c, nom, l, n in listas_en_uso() if n]" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
