# -*- coding: utf-8 -*-
"""La documentacion del panel: una pagina por tema, con categorias y buscador.

Antes era un unico muro con 23 temas seguidos. Lo que se protege aqui es que al
partirla no se pierda ningun tema, que los enlaces antiguos (#cuarentena, #reglas)
sigan llevando a su sitio y que siga existiendo una vista completa para imprimir o
buscar con Ctrl+F.
"""
import ast
import os
import re
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def render(pagina=""):
    """Ejecuta documentacion_page con dobles y devuelve el HTML."""
    fn = None
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name == "documentacion_page":
            fn = n
            break
    assert fn, "no se encontro documentacion_page"
    ns = {"re": re, "html": __import__("html"), "json": __import__("json"),
          "CFG": {"PORT": "5637"},
          "update_box": lambda: "",
          "UPDATE": {"running": False},
          "PANEL_VERSION": "1.1",
          "LOGDIR": "/var/log/suricata",
          "NUNCA_FILE": "/etc/x", "MK_CONF": "/etc/y",
          "nav": lambda activa="": "<!--nav-->"}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<doc>", "exec"), ns)
    return ns["documentacion_page"](pagina=pagina)


def main():
    completo = render("todo")
    temas = re.findall(r'<h2 id="([^"]+)">', completo)
    check("la vista completa conserva TODOS los temas", len(temas) >= 20, len(temas))

    portada = render("")
    # barra lateral
    enlaces = re.findall(r'<a href="\?p=([^"]+)"', portada)
    check("la barra lateral enlaza un tema por pagina", len(enlaces) >= 20, len(enlaces))
    check("no se perdio ningun tema al partir la guia",
          set(temas) - set(enlaces) == set(), sorted(set(temas) - set(enlaces))[:5])

    cats = re.findall(r'<div class=navcat>([^<]+)</div>', portada)
    check("los temas estan agrupados en categorias", len(cats) >= 5, cats)
    for esperada in ("Primeros pasos", "Deteccion", "Cuarentena y MikroTik",
                     "Operacion diaria", "Mantenimiento"):
        check("categoria '%s' presente" % esperada, esperada in cats, cats)

    check("hay buscador", 'id=docq' in portada)
    check("y una vista completa para imprimir o Ctrl+F", '?p=todo' in portada)

    # --- una pagina concreta ---
    uno = render("salud-del-sensor")
    check("abre el tema pedido", "<h1>Salud del sensor</h1>" in uno, uno[:200])
    check("marca ese tema como activo en la barra",
          re.search(r'<a href="\?p=salud-del-sensor" class=on', uno) is not None)
    check("muestra a que categoria pertenece", "docbreadcrumb" in uno)
    check("NO trae los demas temas", uno.count("<h2 id=") <= 1, uno.count("<h2 id="))
    check("tiene navegacion anterior/siguiente", "docpn" in uno and "Siguiente" in uno)

    primero = render(re.sub(r'.*?<a href="\?p=([^"]+)".*', r"\1", portada, flags=re.S))
    check("el primer tema no ofrece 'Anterior'", "pnprev" not in primero, "")

    # --- los enlaces antiguos siguen funcionando ---
    desconocida = render("no-existe-este-tema")
    check("una pagina inexistente cae en la primera, no revienta",
          "<h1>" in desconocida and "docpn" in desconocida)

    # el ancla de cada tema se conserva (los avisos enlazan a #reglas, #cuarentena...)
    check("cada tema conserva su ancla",
          all(('id="%s"' % t) in render(t) for t in temas[:6]), temas[:6])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
