# -*- coding: utf-8 -*-
"""El formulario del MikroTik: conexion por un lado, listas por tipo de abuso por otro.

Lo que estaba mal no era el orden de los campos. El formulario enseñaba LIST y LIST_DNS
como "la lista de cuarentena", y el envio NO manda ahi: enruta por categoria
(clientes-botnet, clientes-dns-malware, clientes-escaneo...). Esas listas, que son las que
de verdad reciben a los CPEs, solo se podian cambiar editando MK_CONF a mano.

Lo que se protege:
  - que haya un campo por categoria, con el nombre por defecto a la vista, para que vacio
    signifique "el de siempre" y se pueda deshacer un cambio sin recordar cual era;
  - que lo configurado en MK_CONF se vea en el campo (si no, guardar el formulario lo
    borraria sin querer);
  - que las listas heredadas sigan ahi, llamadas por su nombre: se usan para sacar a un
    CPE de donde esta y para el diagnostico;
  - y que un nombre con comillas no rompa el HTML: lo pone el ISP y puede llevar lo que sea.
"""
import ast
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("CAT_CPE", "CAT_OTROS", "_card_listas")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def pieza():
    ns = {"html": __import__("html")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def main():
    ns = pieza()
    cats = ns["CAT_CPE"] + [ns["CAT_OTROS"]]

    # --- sin nada configurado: un campo por categoria, vacio, con el defecto a la vista --
    h = ns["_card_listas"]({})
    for cat, nom, _c, por_defecto in cats:
        check("hay campo para '%s'" % cat, "name=lista_%s" % cat in h, "")
        check("  con el nombre por defecto como pista, no como valor",
              'placeholder="%s"' % por_defecto in h
              and 'name=lista_%s value=""' % cat in h, "")
    check("son las ocho (siete categorias mas otros)",
          h.count("name=lista_") == 8, h.count("name=lista_"))

    # --- lo configurado en MK_CONF se ve en el campo ------------------------------------
    # Si no se viera, guardar el formulario mandaria vacio y borraria la configuracion.
    h2 = ns["_card_listas"]({"LISTA_BOTNET": "abusivos-botnet", "LISTA_P2P": "cola-p2p"})
    check("una lista cambiada en MK_CONF aparece en su campo",
          'name=lista_botnet value="abusivos-botnet"' in h2, "")
    check("y otra tambien", 'name=lista_p2p value="cola-p2p"' in h2, "")
    check("las no cambiadas siguen vacias, con su defecto",
          'name=lista_escaneo value=""' in h2, "")

    # --- las heredadas siguen, y dicen que lo son ----------------------------------------
    h3 = ns["_card_listas"]({"LIST": "Cliente Virus", "LIST_DNS": "suricata-dns-sospechoso",
                             "TTL": "2h", "TTL_DNS": "12h"})
    check("la lista de cuarentena heredada sigue en el formulario",
          'name=list value="Cliente Virus"' in h3, "")
    check("y se dice que es heredada, no 'la' lista",
          "heredada" in h3, "")
    check("los TTL se conservan", 'name=ttl value="2h"' in h3 and 'name=ttl_dns value="12h"' in h3, "")

    # --- un nombre con comillas no rompe el HTML -----------------------------------------
    h4 = ns["_card_listas"]({"LISTA_BOTNET": 'mi "lista" <rara>'})
    check("las comillas y los angulos se escapan",
          'value="mi &quot;lista&quot; &lt;rara&gt;"' in h4
          and 'value="mi "lista"' not in h4, h4[h4.find("lista_botnet"):][:90])

    # --- el guardado --------------------------------------------------------------------
    ruta = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta = ruta[:ruta.index('if ruta == "/routers/')]
    check("la ruta guarda las listas por categoria",
          'for _cat, _nom, _cs, _def in CAT_CPE + [CAT_OTROS]:' in ruta
          and '"LISTA_" + _cat.upper()' in ruta, "")
    # vacio = borrar la clave: asi vuelve el nombre por defecto sin tener que escribirlo
    check("un campo vacio borra la clave y vuelve el defecto",
          "m.pop(_k, None)" in ruta, "")
    check("y la conexion y las listas se guardan en el mismo envio",
          'm["HOST"]' in ruta and "lista_" in ruta, "")

    # --- la tarjeta ya no se llama 'cuarentena' a secas ---------------------------------
    check("la tarjeta separa la conexion de lo demas",
          "MikroTik &mdash; conexion" in DASH, "")
    check("y las listas tienen su propio apartado",
          "Listas por tipo de abuso" in DASH, "")
    check("que explica por que son distintas",
          "una botnet se corta, el P2P se encola" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
