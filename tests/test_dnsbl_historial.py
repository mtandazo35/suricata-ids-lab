# -*- coding: utf-8 -*-
"""Historial de listas negras: cuando entro una IP, en cual, y cuanto tardo en salir.

Antes solo se guardaba el estado ACTUAL y se sobreescribia en cada revision. Se veia
cuantas direcciones estaban listadas, pero no cuando entro ninguna ni cuanto tardo en
salir, que es justo lo que hace falta para demostrarle a quien deslista que la causa se
limpio. Y no se puede reconstruir despues: cada revision sin anotarlo era informacion
perdida para siempre.

Lo que se protege:
  - que la PRIMERA revision no invente eventos. Lo que esta listado hoy puede llevar
    meses ahi; apuntarlo como "entro ahora" seria inventarse una fecha y hacer creer que
    el problema es nuevo.
  - que una salida diga cuanto estuvo, contando desde SU entrada y no desde otra anterior
    ya cerrada.
  - que revisar sin cambios no genere ruido.
  - y que el historial no crezca sin fin.
"""
import ast
import os
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("DNSBL_DIAS", "DNSBL_EVENTOS_MAX", "dnsbl_cambios", "_dura",
          "dnsbl_historial_html")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno():
    ns = {"time": time, "html": __import__("html")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def estado(*pares):
    """estado(("1.2.3.4", ["Spamhaus ZEN - XBL: equipo infectado"]), ...)"""
    return {"ips": {ip: {"listas": list(ls)} for ip, ls in pares}}


XBL = "Spamhaus ZEN - XBL: equipo infectado"
SPAMCOP = "SpamCop"
T0 = 1790000000


def main():
    ns = entorno()
    cambios = ns["dnsbl_cambios"]

    # --- la primera revision NO inventa nada -------------------------------------------
    h = {"dias": {}}                                   # sin 'ips': nunca se ha revisado
    evs = cambios(h, estado(("1.2.3.4", [XBL])), ahora=T0)
    check("la primera revision no genera eventos: no se sabe desde cuando estaba",
          evs == [], evs)

    # --- a partir de ahi, los cambios si se anotan ---------------------------------------
    h = {"ips": {}, "eventos": []}
    evs = cambios(h, estado(("1.2.3.4", [XBL])), ahora=T0)
    check("una IP que aparece se anota como ENTRO", len(evs) == 1 and evs[0]["ev"] == "entra", evs)
    check("con la lista y el motivo, no solo el nombre", evs[0]["lista"] == XBL, evs[0])
    check("y con la direccion concreta", evs[0]["ip"] == "1.2.3.4", evs[0])

    # --- revisar sin cambios no ensucia -----------------------------------------------------
    h = {"ips": {"1.2.3.4": {"listas": [XBL]}}, "eventos": list(evs)}
    igual = cambios(h, estado(("1.2.3.4", [XBL])), ahora=T0 + 21600)
    check("revisar y que todo siga igual no anade nada", len(igual) == 1, igual)

    # --- la salida, con cuanto estuvo ---------------------------------------------------------
    sale = cambios(h, estado(), ahora=T0 + 3 * 86400)
    check("cuando desaparece se anota SALIO", sale[-1]["ev"] == "sale", sale[-1])
    check("y dice cuanto estuvo, contado desde su entrada",
          sale[-1]["estuvo"] == 3 * 86400, sale[-1])
    check("en un formato que se lee de un vistazo", ns["_dura"](3 * 86400) == "3 d",
          ns["_dura"](3 * 86400))
    check("tambien con horas sueltas", ns["_dura"](90000) == "1 d 1 h", ns["_dura"](90000))
    check("y por debajo de un dia", ns["_dura"](7200) == "2 h", ns["_dura"](7200))

    # --- reincidencia: entro, salio y volvio ---------------------------------------------------
    # Es el caso que importa operativamente: si vuelve, la causa no se limpio. Y el "estuvo"
    # de la segunda salida tiene que contar desde la SEGUNDA entrada, no desde la primera.
    h2 = {"ips": {}, "eventos": list(sale)}
    vuelve = cambios(h2, estado(("1.2.3.4", [XBL])), ahora=T0 + 10 * 86400)
    h3 = {"ips": {"1.2.3.4": {"listas": [XBL]}}, "eventos": vuelve}
    sale2 = cambios(h3, estado(), ahora=T0 + 12 * 86400)
    check("una reincidencia se ve como entrada nueva",
          [e["ev"] for e in sale2[-2:]] == ["entra", "sale"], sale2[-2:])
    check("y su duracion cuenta desde la SEGUNDA entrada, no desde la primera",
          sale2[-1]["estuvo"] == 2 * 86400, sale2[-1])

    # --- varias listas a la vez ------------------------------------------------------------------
    h4 = {"ips": {"9.9.9.9": {"listas": [XBL]}}, "eventos": []}
    dos = cambios(h4, estado(("9.9.9.9", [XBL, SPAMCOP])), ahora=T0)
    check("entrar en una segunda lista es su propio evento",
          len(dos) == 1 and dos[0]["lista"] == SPAMCOP, dos)

    # --- el historial no crece sin fin -------------------------------------------------------------
    viejos = [{"ts": T0 - (ns["DNSBL_DIAS"] + 5) * 86400, "ip": "5.5.5.5",
               "lista": XBL, "ev": "entra"}]
    h5 = {"ips": {}, "eventos": viejos}
    podado = cambios(h5, estado(), ahora=T0)
    check("lo mas viejo que la ventana se poda", podado == [], podado)
    muchos = [{"ts": T0, "ip": "6.6.6.%d" % (i % 250), "lista": XBL, "ev": "entra"}
              for i in range(ns["DNSBL_EVENTOS_MAX"] + 50)]
    h6 = {"ips": {}, "eventos": muchos}
    check("y hay un tope por entrada",
          len(cambios(h6, estado(), ahora=T0)) == ns["DNSBL_EVENTOS_MAX"],
          len(cambios(h6, estado(), ahora=T0)))

    # --- lo que se ve ------------------------------------------------------------------------------
    htm = ns["dnsbl_historial_html"]({"eventos": sale2})
    check("el bloque sale con los movimientos", "Historial de listas negras" in htm, htm[:80])
    check("distingue entradas de salidas", "ENTRO" in htm and "SALIO" in htm, "")
    check("y avisa de lo que significa reincidir", "no se limpio" in htm, "")
    check("sin movimientos no se pinta nada", ns["dnsbl_historial_html"]({}) == "")
    check("ni con la lista vacia", ns["dnsbl_historial_html"]({"eventos": []}) == "")

    # --- lo que NO tiene que ensuciar el historial ------------------------------------
    # La PBL en un rango residencial es lo NORMAL: el panel ya la cuenta aparte y no la
    # pinta en rojo. Anotar sus idas y venidas llenaria el historial de movimientos que no
    # significan nada y taparia los que si. Paso en el piloto: dos lineas de PBL fueron los
    # dos primeros movimientos que se vieron.
    PBL = "Spamhaus ZEN - PBL: rango dinamico (normal en residencial)"
    h7 = {"ips": {}, "eventos": []}
    check("entrar en la PBL no es un movimiento",
          cambios(h7, estado(("7.7.7.7", [PBL])), ahora=T0) == [], "")
    h8 = {"ips": {"7.7.7.7": {"listas": [PBL]}}, "eventos": []}
    check("ni salir de ella",
          cambios(h8, estado(), ahora=T0) == [], "")
    check("pero si la IP tambien esta en una lista de verdad, ESA si se anota",
          len(cambios(h7, estado(("7.7.7.7", [PBL, XBL])), ahora=T0)) == 1, "")

    # Una consulta DNS que falla no es "limpia": la IP desaparece del estado y sin esto el
    # historial diria que SALIO de la lista. Una buena noticia inventada es lo peor que
    # puede dar esto, porque llevaria a pedir el deslistado creyendo que ya esta limpio.
    h9 = {"ips": {"8.8.8.8": {"listas": [XBL]}}, "eventos": []}
    nada = dict(estado(), inciertas=["8.8.8.8"])
    check("si no se pudo consultar, NO se anota que salio",
          cambios(h9, nada, ahora=T0) == [], cambios(h9, nada, ahora=T0))
    check("y cuando se puede consultar de verdad, si",
          len(cambios(h9, estado(), ahora=T0)) == 1, "")


    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
