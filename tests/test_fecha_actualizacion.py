# -*- coding: utf-8 -*-
"""Cuando se actualizo el panel por ultima vez.

La linea decia de que version a cual y por quien, pero no CUANDO. Sin fecha no se puede
responder a "esto esta al dia?", que es justo para lo que se mira esa tarjeta.

Lo que se protege:
  - que salga la fecha y ademas cuanto hace: un panel actualizado hace tres meses se leia
    igual que uno de esta manana;
  - que tambien se vea cuando la actualizacion NO salio del boton (por SSH o por el cron),
    porque entonces no hay registro de quien la hizo pero la fecha si esta;
  - y que un reloj movido no haga inventar una antiguedad absurda.
"""
import ast
import io
import os
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("panel_actualizado", "panel_actualizado_txt")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(ruta):
    ns = {"time": time}
    fuente = "\n".join(
        (ast.get_source_segment(DASH, n) or "")
        for n in ARBOL.body if getattr(n, "name", "") in PIEZAS)
    exec(fuente.replace('"/etc/suricata-dashboard.updated"', repr(ruta)), ns)
    return ns


def escribir(ruta, cuando):
    io.open(ruta, "w", encoding="utf-8", newline="\n").write(
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cuando)) + "\n")


def main():
    tmp = tempfile.mkdtemp()
    ruta = os.path.join(tmp, "updated")
    ns = entorno(ruta)
    ahora = time.time()

    # --- sin archivo, no se inventa nada ------------------------------------------------
    check("sin registro no se dice nada", ns["panel_actualizado_txt"]() == "",
          ns["panel_actualizado_txt"]())

    # --- recien actualizado --------------------------------------------------------------
    escribir(ruta, ahora - 300)
    t = ns["panel_actualizado_txt"]()
    check("sale la fecha y la hora", time.strftime("%Y-%m-%d %H:%M", time.localtime(ahora - 300)) in t, t)
    check("y cuanto hace, en minutos", "hace 5 min" in t, t)

    # --- hace horas / dias -----------------------------------------------------------------
    escribir(ruta, ahora - 3 * 3600)
    check("en horas cuando toca", "hace 3 h" in ns["panel_actualizado_txt"](),
          ns["panel_actualizado_txt"]())
    escribir(ruta, ahora - 45 * 86400)
    t = ns["panel_actualizado_txt"]()
    check("y en dias cuando lleva tiempo", "hace 45 dia(s)" in t, t)
    # Sin la antiguedad, esa fecha se lee igual que la de esta manana y nadie se entera de
    # que lleva mes y medio sin actualizar.
    check("la fecha sigue estando, no solo el 'hace'",
          time.strftime("%Y-%m-%d", time.localtime(ahora - 45 * 86400)) in t, t)

    # --- un reloj movido no hace inventar ------------------------------------------------------
    escribir(ruta, ahora + 7200)
    t = ns["panel_actualizado_txt"]()
    check("con fecha futura se muestra tal cual, sin antiguedad absurda",
          "hace" not in t and t.strip() != "", t)

    # --- basura en el archivo ---------------------------------------------------------------------
    io.open(ruta, "w", encoding="utf-8", newline="\n").write("no es una fecha\n")
    check("si el archivo trae basura se devuelve tal cual, sin reventar",
          ns["panel_actualizado_txt"]() == "no es una fecha", ns["panel_actualizado_txt"]())

    # --- la linea del panel ------------------------------------------------------------------------
    check("la fecha entra en la linea de 'Actualizado de X a Y'",
          "el <b>{esc(_cuando)}</b>" in DASH, "")
    # Actualizar por SSH o por cron no deja registro de quien ni de que version, pero la
    # fecha si: sin este caso, esos paneles no mostrarian nada.
    check("y si no hubo boton, se muestra igual la fecha",
          "Ultima actualizacion:" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
