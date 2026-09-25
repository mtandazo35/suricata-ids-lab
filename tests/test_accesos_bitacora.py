# -*- coding: utf-8 -*-
"""Accesos y Bitacora: cada pestana responde una sola pregunta.

Lo que protege:
  - Que el Log dejo de repetir la bitacora. Las dos paginas ensenaban casi lo mismo
    porque mk_log() escribe cada cuarentena TAMBIEN en la bitacora, y los logins
    correctos van igualmente a las dos. Con dos pestanas gemelas nadie sabe cual mirar.
  - Que al quitarlo NO se perdio nada: las cuarentenas siguen estando en la bitacora.
  - Que los intentos FALLIDOS siguen saliendo en Accesos. Son el unico dato que no esta
    en la bitacora (solo anota los logins que entraron), asi que si se cayeran de aqui
    una fuerza bruta contra el panel no se veria en ninguna parte.
"""
import ast
import io
import os
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("LOG_RETENCION_DIAS", "_cola_lineas", "_ev_ts", "accesos_recientes",
          "log_page", "bitacora_page", "BITACORA_LOG", "LOGIN_LOG", "MK_LOG")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"os": os, "time": time, "io": io, "html": __import__("html"),
          "BASE_CSS": "/*base*/", "nav": lambda r: "<div class=nav></div>"}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["LOGIN_LOG"] = os.path.join(tmp, "login.log")
    ns["MK_LOG"] = os.path.join(tmp, "cuarentena.log")
    ns["BITACORA_LOG"] = os.path.join(tmp, "bitacora.log")
    return ns


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # --- lo que hay en cada archivo ------------------------------------------------------
    io.open(ns["LOGIN_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:00:00\t203.0.113.7\tadmin\tOK\n"
        "2026-09-25 09:05:00\t198.51.100.4\tadmin\tFAIL\n"
        "2026-09-25 09:06:00\t198.51.100.4\tadmin\tBLOQUEADO\n")
    io.open(ns["MK_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:10:00 ENVIADO 192.168.1.50 por=admin botnet\n")
    # mk_log() ya la habia escrito aqui tambien: por eso se veia dos veces
    io.open(ns["BITACORA_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:00:00\tadmin\t203.0.113.7\tLOGIN\trol=admin\n"
        "2026-09-25 09:10:00\tadmin\t203.0.113.7\tENVIADO\t192.168.1.50 botnet\n"
        "2026-09-25 09:20:00\tadmin\t203.0.113.7\tCONFIG-MIKROTIK\thost=192.0.2.1 enviar=si\n")

    # --- la fuente de Accesos ------------------------------------------------------------
    rec = ns["accesos_recientes"]()
    check("cada intento de acceso es una fila", len(rec) == 3, rec)
    check("y viene mas nuevo primero", rec[0][0] > rec[-1][0], [r[0] for r in rec])
    check("con fecha, IP, usuario y resultado",
          rec[0] == ("2026-09-25 09:06:00", "198.51.100.4", "admin", "BLOQUEADO"), rec[0])
    check("la cuarentena ya NO entra por aqui",
          not any("192.168.1.50" in " ".join(r) for r in rec), rec)

    # --- la pagina de Accesos --------------------------------------------------------------
    acc = ns["log_page"]()
    check("se llama Accesos al panel", "<h1>Accesos al panel</h1>" in acc, acc[:400])
    check("los intentos fallidos se ven: son el unico sitio donde estan",
          "FAIL" in acc and "BLOQUEADO" in acc, "")
    check("y el que entro tambien", "OK" in acc, "")
    check("no se listan cuarentenas", "192.168.1.50" not in acc, "")
    check("ni queda la columna Tipo, que solo servia para separarlas",
          "<th>Tipo</th>" not in acc, "")
    check("y manda a la Bitacora para saber que se hizo dentro",
          "Bitacora" in acc, "")

    # --- lo que NO se perdio ----------------------------------------------------------------
    bit = ns["bitacora_page"]()
    check("la cuarentena sigue estando en la bitacora, con su IP",
          "192.168.1.50" in bit, "")
    check("junto a los cambios de configuracion", "CONFIG-MIKROTIK" in bit, "")
    check("y al login que si entro", "LOGIN" in bit, "")

    # --- la separacion, dicha de una vez ------------------------------------------------------
    # Si algun dia vuelve a leerse MK_LOG desde Accesos, esto lo caza.
    fuente = ast.get_source_segment(DASH, next(
        n for n in ARBOL.body
        if getattr(n, "name", "") == "accesos_recientes")) or ""
    check("Accesos no vuelve a leer el log de cuarentena", "MK_LOG" not in fuente, fuente)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
