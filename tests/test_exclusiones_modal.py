# -*- coding: utf-8 -*-
"""El alta de exclusiones vive en un modal, no ocupando media pagina.

Lo que protege:
  - que la lista (que es lo que se consulta) quede arriba y el formulario detras de un
    boton;
  - que al pulsar Editar el modal se abra SOLO y con la regla cargada: si hubiera que
    abrirlo a mano, "Editar" no haria nada visible y pareceria roto;
  - y que al cerrar una edicion se vuelva a la lista limpia. La URL lleva ?edit=N, asi que
    si solo se ocultara el modal, recargar lo abriria otra vez con la regla vieja.
"""
import ast
import os
import re
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("EXCL_FILE", "cargar_exclusiones", "guardar_exclusiones", "exclusiones_page")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    import html as _h
    import json as _j
    import time as _t
    ns = {"os": os, "json": _j, "time": _t, "html": _h, "re": re,
          "BASE_CSS": "/*base*/", "nav": lambda r: "<div class=nav></div>"}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["EXCL_FILE"] = os.path.join(tmp, "excl.json")
    _j.dump([{"tipo": "dst", "ip": "10.66.66.2", "puertos": [53], "sid": "",
              "motivo": "DNS interno", "hasta": 0}],
            open(ns["EXCL_FILE"], "w", encoding="utf-8"))
    return ns


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # --- la pagina normal ---------------------------------------------------------------
    pag = ns["exclusiones_page"]()
    check("la lista sale con su boton de agregar",
          "class=exhead" in pag and "abrirEx()" in pag, "")
    check("el formulario esta dentro del modal", "class=exmodal" in pag, "")
    check("y el modal viene cerrado", 'data-edit="0"' in pag, "")
    check("la lista va ANTES que el modal, que es lo que se consulta",
          pag.find("<tbody>") < pag.find("class=exmodal"), "")
    check("los campos siguen estando: IP, puertos, firma, vigencia y motivo",
          all(x in pag for x in ("name=ip", "name=puertos", "name=sid",
                                 "name=vigencia", "name=motivo")), "")
    check("se puede cerrar con Escape", "Escape" in pag, "")

    # --- al pulsar Editar ---------------------------------------------------------------
    ed = ns["exclusiones_page"](edit_idx=0)
    check("editar marca el modal para abrirse solo", 'data-edit="1"' in ed, "")
    check("y trae la regla cargada", 'value="10.66.66.2"' in ed, "")
    check("con el indice, para no crear una nueva",
          'name=editar value="0"' in ed, "")
    check("el boton dice que se guardan cambios", "Guardar cambios" in ed, "")

    # --- lo que no puede pasar -----------------------------------------------------------
    # Si al cerrar solo se ocultara, la URL seguiria con ?edit=0 y una recarga reabriria el
    # modal con la regla vieja, encima de una lista que quiza ya cambio.
    check("al cerrar una edicion se vuelve a la lista limpia",
          "location.href='/exclusiones'" in ed, "")
    check("un indice fuera de rango no abre nada",
          'data-edit="0"' in ns["exclusiones_page"](edit_idx=99), "")

    # --- una exclusion de las del .conf no se puede editar --------------------------------
    # Las legacy (motivo '(conf)') no viven en el JSON: ofrecer editarlas seria mentir.
    ns["cargar_exclusiones"] = lambda incluir_vencidas=False: [
        {"tipo": "dst", "ip": "8.8.8.8", "puertos": [], "sid": "", "motivo": "(conf)",
         "hasta": 0}]
    check("una exclusion heredada del .conf no abre el editor",
          'data-edit="0"' in ns["exclusiones_page"](edit_idx=0), "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
