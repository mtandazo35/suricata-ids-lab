# -*- coding: utf-8 -*-
"""Verificador de reglas: lo que RouterOS acepta sin quejarse y no es lo que querias.

Nace del bloque de spam que pego el ISP: reglas en prerouting sin lista (afectan a toda
la red), port= en vez de dst-port=, un comentario "Acepta" en un drop y un jump a una
cadena que no estaba en el bloque. Lo que se protege:
  - las plantillas del panel salen LIMPIAS (ni errores ni avisos): si una plantilla nueva
    no pasa su propio verificador, la prueba lo dice;
  - las reglas del ISP de botnet, DNS y escaneo, tal cual, no tienen errores;
  - el bloque de spam da los avisos que tiene que dar, y NINGUN error (funciona en su
    router: se respeta, se informa);
  - los errores de verdad bloquean: accion inexistente, puerto sin protocolo, regla
    inalcanzable, drop sin criterio en prerouting, NAT en la cadena equivocada, jump sin
    destino; y guardar_reglas_propias los rechaza;
  - contra el router: interface-list inexistente = error; cadena de jump vacia y
    address-list vacia = aviso;
  - aplicar no toca el router con errores; tras aplicar se relee y se dice si el router
    guardo algo distinto (valor normalizado), o "Verificado" si coincide.
"""
import ast
import json
import os
import re
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "tests"))
import test_acciones_router as base      # el RouterOS de mentira y el entorno

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def niveles(ver):
    return [v["nivel"] for v in ver]


def tiene(ver, nivel, trozo):
    return any(v["nivel"] == nivel and trozo in v["msg"] for v in ver)


BOTNET = """/ip firewall raw
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS UDP 53 para clientes en cuarentena" dst-port=53 protocol=udp
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS TCP 53 para clientes en cuarentena" dst-port=53 protocol=tcp
add action=return chain=BOTNET-CUARENTENA comment="Permite navegacion HTTP y HTTPS TCP 80 y 443 para clientes en cuarentena" dst-port=80,443 protocol=tcp
add action=drop chain=BOTNET-CUARENTENA comment="Bloquea cualquier otro protocolo y puerto para clientes en cuarentena"
add action=jump chain=prerouting comment="Restringe clientes botnet exclusivamente a DNS HTTP y HTTPS" jump-target=BOTNET-CUARENTENA place-before=0 src-address-list=clientes-botnet
"""
SPAM = """/ip firewall raw
add action=drop chain=prerouting comment="Bloquea envio SMTP TCP desde clientes identificados generando SPAM" dst-port=25,465,587,2525 place-before=0 protocol=tcp src-address-list=clientes-spam
add action=jump chain=prerouting comment="Aplica control de correo y SPAM a abonados de redes privadas" in-interface-list=!WAN jump-target=Correo-ISP src-address-list=Redes-Privadas place-before=[find where chain=prerouting comment="Drop Malware"]
add action=accept chain=prerouting comment="Acepta correo en todos los puertos si es correo valido" dst-port=465,587,993,995,110 protocol=tcp src-address-list="Correo Permitido"
add action=drop chain=prerouting comment="Acepta correo en todos los puertos si es correo valido" dst-port=465,587,993,995,110 protocol=tcp
add action=drop chain=prerouting comment="Descarta correo en todos los puertos si es correo invalido" port=25,2525 protocol=tcp
add action=drop chain=prerouting comment="Descarta correo en todos los puertos si es correo invalido" port=25,2525 protocol=udp
"""


def main():
    ns, rt, m, logs, td = base.entorno()
    V = ns["verificar_reglas"]; P = ns["reglas_desde_rsc"]; R = ns["reglas_de_accion"]

    # ---------- las plantillas del panel, limpias ----------
    sucias = []
    for cat, acciones in ns["ACCIONES_POR_CAT"].items():
        for ac in acciones:
            if ac in ("propias", "nada"):
                continue
            regl = R(cat, ac, "clientes-" + cat, {"wan": "WAN", "limite": "2M", "dns_ip": ""})
            v = V(regl, "clientes-" + cat)
            if v:
                sucias.append((cat, ac, [x["msg"][:60] for x in v]))
    check("todas las plantillas pasan su propio verificador sin errores ni avisos", not sucias, sucias)

    # ---------- las reglas del ISP ----------
    vb = V(P(BOTNET, "clientes-botnet"), "clientes-botnet")
    check("botnet del ISP: limpia", vb == [], vb)
    vs = V(P(SPAM, "clientes-spam"), "clientes-spam")
    check("spam del ISP: NINGUN error (funciona en su router)", "error" not in niveles(vs), [x["msg"] for x in vs if x["nivel"] == "error"])
    check("  avisa de la regla que mira otra lista (Redes-Privadas)", tiene(vs, "aviso", "usa la lista 'Redes-Privadas'"), vs)
    check("  avisa de las que no miran ninguna lista: afectan a TODO el trafico", tiene(vs, "aviso", "afecta a TODO el trafico"), "")
    check("  avisa de port= (tambien corta respuestas)", tiene(vs, "aviso", "port= casa el puerto de ORIGEN o de DESTINO"), "")
    check("  avisa del comentario 'Acepta' en un drop", tiene(vs, "aviso", "el comentario dice que acepta/permite, pero la accion es drop"), "")
    check("  avisa del jump a una cadena que no esta en el bloque", tiene(vs, "aviso", "salta a 'Correo-ISP'"), "")
    check("  y dice en que linea", any(x["donde"] == "linea 6" and "port=" in x["msg"] for x in vs), [x["donde"] for x in vs])

    # ---------- errores de verdad ----------
    def err(texto, trozo):
        v = V(P(texto, "L"), "L")
        return tiene(v, "error", trozo), v
    casos = [
        ("/ip firewall raw\nadd chain=prerouting action=dst-nat src-address-list=L to-addresses=192.0.2.1", "no existe en /ip firewall raw"),
        ("/ip firewall raw\nadd chain=prerouting action=drop src-address-list=L dst-port=25", "solo vale con protocol"),
        ("/ip firewall raw\nadd chain=prerouting action=drop\nadd chain=prerouting action=drop src-address-list=L protocol=tcp dst-port=25",
         "nunca se evalua"),
        ("/ip firewall raw\nadd chain=prerouting action=drop", "corta TODO el trafico del router"),
        ("/ip firewall nat\nadd chain=srcnat action=dst-nat src-address-list=L to-addresses=192.0.2.1", "va en dstnat"),
        ("/ip firewall raw\nadd chain=prerouting action=jump src-address-list=L", "necesita jump-target"),
        ("/ip firewall raw\nadd chain=prerouting action=jump jump-target=prerouting src-address-list=L", "cadena del sistema"),
    ]
    for texto, trozo in casos:
        ok, v = err(texto, trozo)
        check("error: " + trozo, ok, [x["msg"] for x in v])
    check("una cadena propia a la que no salta nadie es aviso", tiene(V(P("/ip firewall raw\nadd chain=HUERFANA action=drop", "L"), "L"),
                                                                     "aviso", "no la usa ningun jump"), "")

    # guardar rechaza los errores del verificador, y guarda con avisos
    ns["REGLAS_DIR"] = os.path.join(td, "reglas_v")
    try:
        ns["guardar_reglas_propias"]("spam", "/ip firewall raw\nadd chain=prerouting action=drop"); g = ""
    except ValueError as ex:
        g = str(ex)
    check("guardar rechaza un drop sin criterio en prerouting", "corta TODO" in g and not ns["cargar_reglas_propias"]("spam"), g)
    check("y guarda el bloque de spam del ISP (solo avisos)", ns["guardar_reglas_propias"]("spam", SPAM) == 6, "")

    # ---------- contra el router ----------
    rt.t["/interface/list"] = [{".id": "*1", "name": "LAN"}]                 # sin WAN
    rt.t["/ip/firewall/address-list"] = [{".id": "*9", "list": "Redes-Privadas", "address": "10.0.0.0/8"}]
    vr = ns["verificar_en_router"](rt, P(SPAM, "clientes-spam"), "clientes-spam")
    check("interface-list que no existe en el router: error", tiene(vr, "error", "no existe la interface-list 'WAN'"), vr)
    check("cadena de jump vacia en el router: aviso", tiene(vr, "aviso", "la cadena 'Correo-ISP' no existe ni en el bloque ni en el router"), vr)
    check("address-list vacia en el router: aviso ('Correo Permitido')", tiene(vr, "aviso", "'Correo Permitido' esta vacia"), vr)
    check("la que tiene entradas no avisa (Redes-Privadas)", not tiene(vr, "aviso", "'Redes-Privadas' esta vacia"), "")

    # ---------- aplicar: bloqueado con errores; verificado tras aplicar ----------
    router = {"id": "r1"}
    ns["RESPALDOS_MK"] = os.path.join(td, "bk_v")
    m["ACCION_DNS"] = "dns-protegido"                                    # usa !WAN: el router no la tiene
    antes = json.dumps(rt.t, sort_keys=True)
    okb, msgb, planb = ns["aplicar_reglas"](router, "dns", quien="admin")
    check("con un error del verificador, aplicar no toca el router", okb is False and "verificador encontro errores" in msgb
          and json.dumps(rt.t, sort_keys=True) == antes and not os.path.exists(ns["RESPALDOS_MK"]), msgb)
    check("  y la vista previa lo marca como bloqueado", planb.get("bloqueado") is True, "")
    rt.t["/interface/list"].append({".id": "*2", "name": "WAN"})
    okc, msgc, _ = ns["aplicar_reglas"](router, "dns", quien="admin")
    check("con la WAN creada: aplica y verifica releyendo el router", okc and "Verificado" in msgc, msgc)

    # el router guarda un valor normalizado: se dice cual y como
    for f in rt.t["/ip/firewall/raw"]:
        if f.get("dst-limit"):
            f["dst-limit"] = "50,100,src-address/10s,1m"
    orig_resp = rt.responder
    def responder_normaliza():
        w = rt.pend
        r = orig_resp()
        if w and w[0].endswith("/set"):                                    # el router vuelve a normalizar
            for f in rt.t["/ip/firewall/raw"]:
                if f.get("dst-limit") == "50,100,src-address/10s":
                    f["dst-limit"] = "50,100,src-address/10s,1m"
        return r
    rt.responder = responder_normaliza
    okd, msgd, _ = ns["aplicar_reglas"](router, "dns", quien="admin")
    check("si el router guarda distinto, se dice campo, lo mandado y lo guardado",
          okd and "OJO" in msgd and "dst-limit" in msgd and "50,100,src-address/10s,1m" in msgd, msgd)
    check("  y queda en la bitacora", any(a == "REGLAS-DIFIEREN" for a, _d in logs), "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
