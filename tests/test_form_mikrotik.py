# -*- coding: utf-8 -*-
"""El formulario del MikroTik: conexion por un lado, listas por tipo de abuso por otro.

Lo que estaba mal no era el orden de los campos. El formulario enseñaba LIST y LIST_DNS
como "la lista de cuarentena", y el envio NO manda ahi: enruta por categoria
(clientes-botnet, clientes-dns-malware, clientes-escaneo...). Esas listas, que son las que
de verdad reciben a los CPEs, solo se podian cambiar editando MK_CONF a mano.

Lo que se protege:
  - que haya un campo por categoria con el nombre por defecto CARGADO (editable); vacio o
    el propio defecto significan "el de siempre" y no se guardan como cambio;
  - que lo configurado en MK_CONF se vea en el campo (si no, guardar el formulario lo
    borraria sin querer);
  - que las listas heredadas ya NO esten en el formulario: ningun envio nuevo va ahi.
    Pero la CLAVE se conserva en el .conf -libera entradas anteriores al enrutado por
    categoria, sirve al diagnostico y de guardia-, asi que la ruta no puede borrarla al
    guardar un formulario que ya no la trae;
  - que los TTL si sigan: son vivos para todas las listas, tambien las de categoria;
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
        check("  con el nombre por defecto CARGADO como valor (editable)",
              'name=lista_%s value="%s"' % (cat, por_defecto) in h, "")
    check("son las ocho (siete categorias mas otros)",
          h.count("name=lista_") == 8, h.count("name=lista_"))

    # --- lo configurado en MK_CONF se ve en el campo ------------------------------------
    # Si no se viera, guardar el formulario mandaria vacio y borraria la configuracion.
    h2 = ns["_card_listas"]({"LISTA_BOTNET": "abusivos-botnet", "LISTA_P2P": "cola-p2p"})
    check("una lista cambiada en MK_CONF aparece en su campo",
          'name=lista_botnet value="abusivos-botnet"' in h2, "")
    check("y otra tambien", 'name=lista_p2p value="cola-p2p"' in h2, "")
    check("las no cambiadas traen su defecto cargado",
          'name=lista_escaneo value="clientes-escaneo"' in h2, "")

    # --- las heredadas ya no se ensenan; los TTL si ---------------------------------------
    # Ningun envio nuevo va a LIST ni a LIST_DNS: ensenarlas como "la lista de cuarentena"
    # era prometer un destino y usar otro. Fuera del formulario.
    h3 = ns["_card_listas"]({"LIST": "Cliente Virus", "LIST_DNS": "suricata-dns-sospechoso",
                             "TTL": "2h", "TTL_DNS": "12h"})
    check("la lista de cuarentena heredada ya no esta en el formulario",
          "name=list " not in h3 and "name=list value" not in h3, h3[-400:])
    check("ni la de DNS heredada", "name=list_dns" not in h3, "")
    check("y ya no se habla de 'heredadas'", "heredada" not in h3, "")
    # el TTL es vivo: cuanto dura cada entrada en el router, en todas las listas
    check("los TTL siguen, que son vivos",
          'name=ttl value="2h"' in h3 and 'name=ttl_dns value="12h"' in h3, "")
    check("bajo un apartado de caducidad a secas", "Caducidad</h3>" in h3, "")

    # La clave NO puede borrarse al guardar: el formulario ya no la manda, asi que la ruta
    # tiene que conservar el valor existente (es lo que libera entradas antiguas).
    ruta_mk = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta_mk = ruta_mk[:ruta_mk.index('if ruta == "/routers/')]
    check("al guardar, LIST se conserva aunque el formulario ya no la traiga",
          'or m.get("LIST", "suricata-cuarentena")' in ruta_mk
          or 'or "suricata-cuarentena"' in ruta_mk, "")

    # Telegram decia que el CPE fue a LIST cuando fue a la de su categoria
    env = DASH[DASH.index("if ruta == \"/cuarentena/enviar\":"):]
    env = env[:env.index("\n        if ruta == ", 10)]
    check("el aviso de Telegram nombra la lista a la que FUE, no la heredada",
          'notificar_cuarentena(ip, "Infeccion CnC", _lst' in env
          and 'notificar_cuarentena(ip, "Infeccion CnC", m.get("LIST"' not in env, "")

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
    # vacio o el propio defecto = borrar la clave: no se guarda el defecto como cambio
    check("un campo vacio o con el defecto borra la clave",
          "m.pop(_k, None)" in ruta and "_v != _def" in ruta, "")
    check("y la conexion y las listas se guardan en el mismo envio",
          'm["HOST"]' in ruta and "lista_" in ruta, "")

    # --- guardar de verdad: lo que la ruta mete en m tiene que llegar al archivo ----------
    # (2026-10-09: guardar_mk escribia una lista fija de claves y tiraba LISTA_* y POL_*;
    # el usuario rellenaba sus listas, guardaba, y volvian vacias)
    import os, tempfile
    ns_g = {"os": os}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in ("guardar_mk", "_mk_globales"):
            exec(ast.get_source_segment(DASH, n) or "", ns_g)
    td = tempfile.mkdtemp(); ns_g["MK_CONF"] = os.path.join(td, "mk.conf")
    ns_g["guardar_mk"]({"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1",
                        "LISTA_BOTNET": "abusivos-botnet", "LISTA_DNS": "clientes-malware",
                        "POL_BOTNET": "alto", "POL_P2P": "nada", "LISTA_SPAM": ""})
    g = ns_g["_mk_globales"]()
    check("guardar_mk conserva las listas por categoria",
          g.get("LISTA_BOTNET") == "abusivos-botnet" and g.get("LISTA_DNS") == "clientes-malware", g)
    check("y las politicas por clase", g.get("POL_BOTNET") == "alto" and g.get("POL_P2P") == "nada", g)
    check("una lista vacia no se escribe (vuelve el defecto)", "LISTA_SPAM" not in g, g)
    check("y lo de siempre sigue", g.get("HOST") == "192.0.2.1" and g.get("ENABLED") == "1", g)

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
