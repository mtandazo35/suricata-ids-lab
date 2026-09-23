# -*- coding: utf-8 -*-
"""La tendencia del abuso saliente: el numero que hay que poder enseñar.

Los reportes HTML se podan a los 3 dias, asi que la tendencia NO se puede reconstruir
desde ellos. Se acumula aparte, y de forma incremental: recontar la ventana daria mal el
total del dia en cuanto alguien la baje de 24 h, y lo haria sin avisar.

Lo que se protege aqui es que los contadores sumen bien entre corridas, que un dia sin
datos se vea como hueco y no como un dia tranquilo, y que la pagina calcule la tendencia
como toca.
"""
import ast
import json
import os
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_g = SRC.index("cat > /usr/local/bin/suricata-html-report <<'HREP'")
GEN = SRC[_g:].split("\n", 1)[1].split("\nHREP\n", 1)[0]
_d = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_d:].split("\n", 1)[1].split("\nDASH\n", 1)[0]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(fuente, nombres, extra=None):
    arbol = ast.parse(fuente)
    ns = {"json": json, "os": os, "time": time, "html": __import__("html"),
          "glob": __import__("glob"), "threading": __import__("threading")}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(fuente, n) or "", ns)
    return ns


def dia(delta):
    return time.strftime("%Y-%m-%d", time.localtime(time.time() + delta * 86400))


def main():
    # ---------- generador: fusion incremental ----------
    g = piezas(GEN, ("METRICAS_DIAS", "METRICAS_MAX_CPES", "fusionar_metricas"))
    fus = g["fusionar_metricas"]

    hoy = dia(0)
    r1 = fus({}, {hoy: {"sal": 100, "ent": 5, "cpes": {"10.0.0.1", "10.0.0.2"},
                        "puertos": {"25/tcp": 80}, "cats": {"Spam": 80}, "nodos": {}}},
             1000, False)
    check("primera corrida: se guarda el dia", r1["dias"][hoy]["sal"] == 100, r1["dias"][hoy])
    check("y la marca de hasta donde se conto", r1["ultimo_ts"] == 1000, r1["ultimo_ts"])

    r2 = fus(r1, {hoy: {"sal": 40, "ent": 2, "cpes": {"10.0.0.2", "10.0.0.9"},
                        "puertos": {"25/tcp": 30, "22/tcp": 10}, "cats": {"Spam": 30}, "nodos": {}}},
             2000, False)
    check("segunda corrida: SUMA, no reemplaza", r2["dias"][hoy]["sal"] == 140, r2["dias"][hoy]["sal"])
    check("los entrantes tambien suman", r2["dias"][hoy]["ent"] == 7, r2["dias"][hoy]["ent"])
    check("los CPEs distintos se unen sin duplicar", r2["dias"][hoy]["cpes_n"] == 3,
          r2["dias"][hoy]["cpes_n"])
    check("los puertos suman y aparecen los nuevos",
          r2["dias"][hoy]["puertos"] == {"25/tcp": 110, "22/tcp": 10}, r2["dias"][hoy]["puertos"])

    # un dia con corte de datos queda marcado
    r3 = fus(r2, {hoy: {"sal": 1, "ent": 0, "cpes": set(), "puertos": {}, "cats": {}, "nodos": {}}},
             3000, True)
    check("un corte de datos deja el dia marcado", r3["dias"][hoy].get("hueco") is True, r3["dias"][hoy])

    # retencion y colapso de la lista de CPEs
    viejo = dia(-10)
    antiguo = dia(-500)
    base = {"dias": {viejo: {"sal": 9, "ent": 0, "cpes": ["10.0.0.7"], "cpes_n": 1,
                             "puertos": {}, "cats": {}, "nodos": {}},
                     antiguo: {"sal": 5, "ent": 0, "cpes_n": 1, "puertos": {}, "cats": {}, "nodos": {}}}}
    r4 = fus(base, {}, 4000, False)
    check("de los dias viejos se guarda el numero, no la lista de CPEs",
          "cpes" not in r4["dias"][viejo] and r4["dias"][viejo]["cpes_n"] == 1, r4["dias"][viejo])
    check("y lo mas viejo que la retencion se cae", antiguo not in r4["dias"], list(r4["dias"]))

    # ---------- panel: contadores de accion y pagina ----------
    tmp = tempfile.mkdtemp()
    d = piezas(DASH, ("ACCIONES_FILE", "ACCIONES_DIAS", "_ACC_LOCK", "cargar_acciones",
                      "contar_accion", "METRICAS_FILE", "cargar_metricas", "_serie",
                      "_media", "_grafico", "historico_page",
                      "GRUPOS_SALIDA", "_cpes_de_reporte", "analisis_salida",
                      "regla_salida", "reglas_salida_texto",
                      "GRUPOS_CONDUCTA", "analisis_conducta", "reglas_conducta_texto",
                      "ENTRANTES_FILE", "BL_LISTA", "BL_MIN_ALERTAS", "BL_MIN_DESTINOS",
                      "BL_TOPE", "_REP_CACHE", "_REP_MAX", "rep_fuente", "cargar_entrantes",
                      "blocklist_borde", "blocklist_rsc", "blocklist_reglas"),
               extra={"BASE_CSS": "", "nav": lambda a="": "<!--nav-->",
                      "wrap": lambda b, refresh=True, active="": b, "LOGDIR": tmp,
                      "cargar_routers": lambda: [{"id": "", "nombre": "MikroTik"}],
                      "ipaddress": __import__("ipaddress"), "re": __import__("re"),
                      "es_mi_cpe": lambda ip: ip.startswith("10."),
                      "nunca_bloquear": lambda ip: False,
                      "FEEDS_META": os.path.join(tmp, "reputation.meta"),
                      "mis_redes": lambda: ["10.0.0.0/8"],
                      "clave_cpe": lambda ip, rid: (rid + "|" + ip) if rid else ip})
    d["ACCIONES_FILE"] = os.path.join(tmp, "acciones.json")
    d["METRICAS_FILE"] = os.path.join(tmp, "metricas.json")
    d["ENTRANTES_FILE"] = os.path.join(tmp, "entrantes.json")

    d["contar_accion"]("ENVIADO"); d["contar_accion"]("ENVIADO"); d["contar_accion"]("QUITADO")
    acc = d["cargar_acciones"]()
    check("las acciones se cuentan por dia", acc[hoy] == {"ENVIADO": 2, "QUITADO": 1}, acc)

    # serie con un dia flojo y otro fuerte para que la tendencia se note
    dias = {}
    for i in range(14, 7, -1):
        dias[dia(-i)] = {"sal": 1000, "ent": 0, "cpes_n": 20, "puertos": {}, "cats": {}}
    for i in range(7, 0, -1):
        dias[dia(-i)] = {"sal": 500, "ent": 0, "cpes_n": 10,
                         "puertos": {"25/tcp": 400}, "cats": {"Spam": 400}}
    dias[hoy] = {"sal": 123, "ent": 4, "cpes_n": 7, "puertos": {"22/tcp": 100},
                 "cats": {"Escaneo SSH": 100}}
    json.dump({"dias": dias}, open(d["METRICAS_FILE"], "w", encoding="utf-8"))

    pag = d["historico_page"](30)
    check("sale el dato de hoy", "123" in pag, "")
    check("y la tendencia a la baja, en verde", "&darr;" in pag and "#3a9d5d" in pag,
          "flecha=%s" % ("&darr;" in pag))
    check("se cuentan las cuarentenas del periodo", "puestos en cuarentena" in pag)
    check("se dice por que atacan", "Spam" in pag and "Escaneo SSH" in pag)
    check("y por que puerto salen", "25/tcp" in pag and "22/tcp" in pag)
    check("hay grafico sin librerias externas", "<svg" in pag and "cdn" not in pag.lower())
    check("los reportes guardados siguen listandose", "Reportes guardados" in pag)

    vacia = d["historico_page"](30)
    json.dump({"dias": {}}, open(d["METRICAS_FILE"], "w", encoding="utf-8"))
    vacia = d["historico_page"](30)
    check("sin historico se explica, no se muestra un cero enganoso",
          "Todavia no hay historico" in vacia)

    # un dia con hueco se pinta distinto
    json.dump({"dias": {hoy: {"sal": 10, "hueco": True, "cpes_n": 1}}},
              open(d["METRICAS_FILE"], "w", encoding="utf-8"))
    ph = d["historico_page"](7)
    check("un dia con datos incompletos no se pinta como bueno",
          "#c8ccd1" in ph and "sensor estuvo parado" in ph)

    # ---------- que cuenta como abuso, y como se nombra ----------
    t = piezas(GEN, ("_TRAD", "traducir", "CATS_NO_ABUSO"), extra={"re": __import__("re")})
    tr = t["traducir"]
    casos = [
        ("ET HUNTING Terse Unencrypted Request for Google - Likely Connectivity Check",
         "Chequeo de conectividad"),
        ("ET HUNTING Suspicious Empty User-Agent", "User-Agent raro"),
        ("GPL WEB_SERVER 403 Forbidden", "Acceso denegado (403)"),
        ("ET SCAN Potential SSH Scan", "Escaneo SSH"),
        ("ET CNC Feodo checkin", "Botnet CnC"),
    ]
    for sig, esperado in casos:
        check("se traduce %r" % sig[:40], tr(sig) == esperado, tr(sig))

    largo = tr("ET FOOBAR Una firma larguisima que nadie tradujo y que no cabe en la columna ni de broma")
    check("una firma sin traducir se acorta y pierde el prefijo del ruleset",
          len(largo) <= 45 and not largo.startswith("ET "), largo)

    check("BitTorrent NO cuenta como abuso saliente", "BitTorrent / P2P" in t["CATS_NO_ABUSO"])
    check("ni un chequeo de conectividad", "Chequeo de conectividad" in t["CATS_NO_ABUSO"])
    check("pero el escaneo SI", "Escaneo SSH" not in t["CATS_NO_ABUSO"])
    check("y la botnet tambien", "Botnet CnC" not in t["CATS_NO_ABUSO"])

    # el ruido se guarda aparte, no se tira ni se suma
    r5 = fus({}, {hoy: {"sal": 10, "ent": 0, "ruido": 900, "cpes": set(),
                        "puertos": {}, "cats": {}, "nodos": {}}}, 5000, False)
    check("el ruido se guarda en su propio contador",
          r5["dias"][hoy]["sal"] == 10 and r5["dias"][hoy]["ruido"] == 900, r5["dias"][hoy])
    r6 = fus(r5, {hoy: {"sal": 5, "ent": 0, "ruido": 100, "cpes": set(),
                        "puertos": {}, "cats": {}, "nodos": {}}}, 6000, False)
    check("y tambien suma entre corridas", r6["dias"][hoy]["ruido"] == 1000, r6["dias"][hoy])

    # ---------- reglas de salida a partir de los eventos reales ----------
    # 3 CPEs mandando spam, 1 escaneando SSH y 1 haciendo solo web (que NO debe generar regla)
    json.dump({"top_riesgo": [
        {"ip": "10.0.0.1", "router": "", "puertos_top": {"25/tcp": 4000}},
        {"ip": "10.0.0.2", "router": "", "puertos_top": {"25/tcp": 3000, "443/tcp": 50}},
        {"ip": "10.0.0.3", "router": "", "puertos_top": {"25/tcp": 1000}},
        {"ip": "10.0.0.4", "router": "", "puertos_top": {"22/tcp": 1500, "23/tcp": 500}},
        {"ip": "10.0.0.5", "router": "", "puertos_top": {"443/tcp": 9000}},
    ], "candidatos": [], "dns_candidatos": []},
        open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))

    tot, n_cpes, grupos = d["analisis_salida"](None)
    check("se miran todos los CPEs con actividad", n_cpes == 5, n_cpes)
    porclave = {g["clave"]: g for g in grupos}
    check("se detecta el correo saliente", "correo" in porclave, list(porclave))
    check("con sus alertas sumadas", porclave["correo"]["alertas"] == 8000, porclave.get("correo"))
    check("y cuantos CPEs lo hacen", porclave["correo"]["cpes"] == 3, porclave.get("correo"))
    check("dice que porcentaje del abuso corta",
          40 < porclave["correo"]["pct"] < 45, porclave["correo"]["pct"])
    check("la administracion remota sale aparte", porclave["admin"]["alertas"] == 2000, porclave.get("admin"))
    check("lo primero que se propone es lo que mas corta", grupos[0]["clave"] == "correo",
          [g["clave"] for g in grupos])
    check("el trafico web normal NO genera ninguna regla",
          all("443" not in g["puertos"] for g in grupos), [g["puertos"] for g in grupos])
    check("y solo se nombran los puertos con abuso de VERDAD",
          porclave["admin"]["puertos"] == ["22", "23"], porclave["admin"]["puertos"])

    txt = d["reglas_salida_texto"](grupos)
    check("la regla sale con TUS redes de abonado", "src-address=10.0.0.0/8" in txt, txt[:200])
    check("y con una lista de excepciones", "src-address-list=!suricata-salida-permitida" in txt)
    check("el correo se corta SOLO en el 25: cortar el 587 rompe a los clientes legitimos",
          "dst-port=25 " in txt and "587" not in txt, txt)

    # --- reglas por CONDUCTA: un escaner no se corta con una regla por puerto ---
    cond = d["analisis_conducta"](None)
    check("sin categorias no se propone ninguna conducta", cond == [], cond)

    json.dump({"top_riesgo": [
        {"ip": "10.0.0.1", "router": "", "puertos_top": {"25/tcp": 4000},
         "cats_top": {"Spam": 4000}},
        {"ip": "10.0.0.4", "router": "", "puertos_top": {"22/tcp": 1500, "23/tcp": 500},
         "cats_top": {"Escaneo SSH": 1200, "Escaneo de puertos": 600, "Fuerza bruta": 200}},
        {"ip": "10.0.0.5", "router": "", "puertos_top": {"443/tcp": 9000},
         "cats_top": {"Anomalia TLS/SSL": 9000}},
    ], "candidatos": [], "dns_candidatos": []},
        open(os.path.join(tmp, "cuarentena.json"), "w", encoding="utf-8"))
    cond = {g["clave"]: g for g in d["analisis_conducta"](None)}
    check("el escaneo se detecta como conducta", "escaneo" in cond, list(cond))
    check("sumando sus categorias", cond["escaneo"]["alertas"] == 1800, cond["escaneo"]["alertas"])
    check("la fuerza bruta va aparte", cond["fuerza"]["alertas"] == 200, cond.get("fuerza"))
    check("el trafico normal no genera conducta",
          all("Anomalia" not in c for g in cond.values() for c, _n in g["cats"]), cond)

    esc_txt = d["reglas_conducta_texto"]("escaneo")
    check("la regla de escaneo usa el detector psd de RouterOS", "psd=" in esc_txt, esc_txt[:120])
    check("y tambien limita las conexiones nuevas (barrido horizontal)",
          "connection-state=new" in esc_txt and "limit=" in esc_txt)
    check("mete al que escanea en una address-list",
          "add-src-to-address-list" in esc_txt and "suricata-escaneo" in esc_txt)
    check("el DROP viene DESACTIVADO: el P2P daria falso positivo",
          "action=drop disabled=yes" in esc_txt, esc_txt[-200:])

    pag_r = d["historico_page"](30)
    check("las reglas se ven en Abuso saliente", "Reglas de salida" in pag_r)
    check("con el porcentaje que corta cada una", "rpct" in pag_r)
    check("y el aviso de excluir el servidor de correo",
          "servidor de correo" in pag_r, "")

    # ---------- bloqueo en el borde: cortar a los que nos atacan ----------
    check("sin datos de entrantes no se propone bloquear a nadie",
          d["blocklist_borde"]() == [], d["blocklist_borde"]())

    # Aqui NO se pueden usar 203.0.113.x ni 198.51.100.x: son rangos de documentacion,
    # no son direcciones publicas enrutables, y el codigo los rechaza a proposito (eso se
    # comprueba mas abajo). Se usan resolutores publicos conocidos como relleno.
    json.dump({"origenes": {
        # golpea fuerte y a muchos: se bloquea
        "1.1.1.1": {"alertas": 900, "destinos": 40, "pais": "CN", "firma": "SSH scan"},
        # una sola alerta contra un solo destino: ruido de fondo de internet
        "8.8.8.8": {"alertas": 1, "destinos": 1, "pais": "US", "firma": "x"},
        # pocas alertas PERO fichada en un feed: entra igual
        "9.9.9.9": {"alertas": 2, "destinos": 1, "pais": "RU", "firma": "y"},
        # una IP nuestra que aparezca por error NO se bloquea jamas
        "10.6.1.10": {"alertas": 5000, "destinos": 80, "pais": "EC", "firma": "z"},
        # un rango de documentacion no es publico: no se bloquea aunque golpee
        "203.0.113.50": {"alertas": 900, "destinos": 40, "pais": "XX", "firma": "w"},
    }}, open(d["ENTRANTES_FILE"], "w", encoding="utf-8"))
    io = __import__("io")
    with io.open(os.path.join(tmp, "reputation.lst"), "w", encoding="utf-8") as fh:
        fh.write("9.9.9.9\tfeodo\n")
    with io.open(os.path.join(tmp, "reputation.meta"), "w", encoding="utf-8") as fh:
        fh.write("{}")

    bl = {x["ip"]: x for x in d["blocklist_borde"]()}
    check("se bloquea al que golpea fuerte y a muchos destinos", "1.1.1.1" in bl, list(bl))
    check("el ruido de fondo NO se bloquea", "8.8.8.8" not in bl, list(bl))
    check("pero si esta fichada en un feed, entra aunque golpee poco",
          "9.9.9.9" in bl and bl["9.9.9.9"]["fuente"] == "feodo", bl.get("9.9.9.9"))
    check("un rango de documentacion no se bloquea: no es una IP publica",
          "203.0.113.50" not in bl, list(bl))
    check("una IP de TUS redes no se bloquea nunca", "10.6.1.10" not in bl, list(bl))
    check("se dice por que esta cada una",
          bl["1.1.1.1"]["alertas"] == 900 and bl["1.1.1.1"]["destinos"] == 40,
          bl["1.1.1.1"])

    rsc = d["blocklist_rsc"]()
    check("el script limpia la lista vieja antes de escribir",
          "remove $i" in rsc and "find list=suricata-atacantes" in rsc, rsc[:200])
    check("y agrega las IPs con caducidad", "add list=suricata-atacantes" in rsc and "timeout=1d" in rsc)
    check("sin meter comillas ni cosas raras en el comentario",
          '"' not in rsc.split("comment=")[1].split('"')[1] if "comment=" in rsc else True)

    reg = d["blocklist_reglas"]()
    check("EL detalle que evita romper clientes: solo conexiones NUEVAS",
          reg.count("connection-state=new") >= 2, reg)
    check("no se corta en raw, que tiraria tambien las respuestas",
          "/ip firewall raw" not in reg, reg)
    check("el router se baja la lista solo, no se le meten miles por la API",
          "/tool fetch" in reg and "scheduler" in reg)
    check("se cubre lo que entra a la red y lo que entra al router",
          "chain=forward" in reg and "chain=input" in reg)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
