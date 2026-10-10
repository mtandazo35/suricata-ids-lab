# -*- coding: utf-8 -*-
"""La ficha de usuario en la barra, a la derecha de Salir.

Se ve con que cuenta se esta dentro (foto o iniciales, nombre, rol) y un clic lleva a
Ajustes. Lo que se protege:
  - sin sesion (panel sin usuarios, o la barra que se arma al cargar el modulo) no sale;
  - sin foto salen las iniciales; con foto, la foto va por /mi-foto?v=<huella> y NO
    incrustada (hasta 300 KB en cada pagina, que se recarga sola);
  - la huella cambia cuando cambia la foto (el navegador no se queda con la vieja);
  - el nombre se escapa (lo escribe el usuario);
  - /mi-foto devuelve la foto del que la pide y nada mas: data: mal formado o que no es
    imagen -> nada;
  - la ficha va despues de Salir en la barra, la ruta va detras del login, y en el movil
    se oculta el nombre.
"""
import ast
import base64
import hashlib
import html
import os
import re
import sys
import types

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


def cargar(nombres, ns):
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name in nombres:
            exec(ast.get_source_segment(DASH, n), ns)
        elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in nombres for t in n.targets):
            exec(ast.get_source_segment(DASH, n), ns)
    return ns


def main():
    USUARIOS = []
    CTX = types.SimpleNamespace(user=None, role=None)
    ns = {"html": html, "hashlib": hashlib, "re": re, "base64": base64, "CTX": CTX,
          "buscar_usuario": lambda u: next((r for r in USUARIOS if r.get("user") == u), None)}
    cargar({"_ROL_TXT", "_AV_COLORS", "_iniciales", "_avatar", "_ficha_yo", "foto_de"}, ns)
    ficha, foto_de = ns["_ficha_yo"], ns["foto_de"]

    check("sin sesion no sale la ficha", ficha() == "", ficha())

    USUARIOS.append({"user": "op1", "role": "operador", "nombre": "Ana Perez"})
    CTX.user, CTX.role = "op1", "operador"
    f = ficha()
    check("sin foto: iniciales, nombre y rol", ">AP<" in f and "Ana Perez" in f and "Operador" in f, f)
    check("  y lleva a Ajustes", 'href="/ajustes"' in f, f)

    png = base64.b64encode(b"\x89PNG\r\n\x1a\nfalso").decode()
    USUARIOS[0]["avatar"] = "data:image/png;base64," + png
    f1 = ficha()
    check("con foto: va por /mi-foto?v=, no incrustada", "/mi-foto?v=" in f1 and "base64" not in f1, f1)
    USUARIOS[0]["avatar"] = "data:image/png;base64," + base64.b64encode(b"\x89PNG otra").decode()
    f2 = ficha()
    v1 = re.search(r"v=(\w+)", f1).group(1); v2 = re.search(r"v=(\w+)", f2).group(1)
    check("  la huella cambia al cambiar la foto", v1 != v2, (v1, v2))

    USUARIOS[0]["nombre"] = '<script>alert(1)</script>'
    check("el nombre se escapa", "<script>" not in ficha(), ficha())

    USUARIOS[0]["nombre"] = ""
    check("sin nombre: sale el usuario", ">op1<" in ficha(), ficha())

    tipo, datos = foto_de("op1")
    check("/mi-foto: tipo y bytes de la foto del que la pide", tipo == "image/png" and datos == b"\x89PNG otra", (tipo, datos))
    check("  de un usuario que no existe: nada", foto_de("nadie") is None, "")
    check("  sin sesion: nada", foto_de(None) is None, "")
    USUARIOS[0]["avatar"] = "data:text/html;base64," + base64.b64encode(b"<script>").decode()
    check("  lo que no es imagen no se sirve", foto_de("op1") is None, "")

    # ---- donde va ----
    check("la ficha va despues de Salir en la barra",
          re.search(r'class="out">Salir</a>\'\s*\+\s*_ficha_yo\(\)', DASH) is not None, "")
    i_ruta = DASH.index('if path == "/mi-foto":')
    i_get = DASH.rindex("def do_GET", 0, i_ruta)
    i_auth = DASH.index("if not self._auth_ok():", i_get)   # la puerta, no el /login de antes
    check("/mi-foto va detras del login", i_auth < i_ruta, (i_auth, i_ruta))
    movil = DASH[DASH.index("@media(max-width:820px){\n .nav .navwrap"):]
    movil = movil[:movil.index("\n}\n")]
    check("en el movil se oculta el nombre (solo la foto)", ".nav .yo .yot{display:none}" in movil, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
