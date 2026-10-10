# -*- coding: utf-8 -*-
"""El menu del usuario, arriba a la derecha (sustituye al boton Salir).

Boton: foto (o iniciales) + nombre + flecha. Panel: nombre y rol, Mi cuenta, Cambiar
contrasena, Cerrar sesion y "Desconectar en", el tiempo que le queda a la sesion.
Lo que se protege:
  - sin sesion (panel sin usuarios, o la barra que se arma al cargar el modulo) queda el
    Salir de siempre y no hay menu;
  - las tres opciones van a donde tienen que ir (Cerrar sesion = /logout);
  - el reloj sale con lo que le queda a la sesion, y no sale si no se sabe (sin exp);
  - sin foto salen las iniciales; con foto, la foto va por /mi-foto?v=<huella> y NO
    incrustada (hasta 300 KB en cada pagina, que se recarga sola); la huella cambia con
    la foto; el nombre se escapa;
  - /mi-foto devuelve la foto del que la pide y nada mas (solo image/*);
  - Ajustes abre lo suyo con #cuenta / #clave: Perfil a lectura/operador, y al admin SU
    fila de Usuarios (no tiene tarjeta Perfil); el nombre que va al JS no puede cerrar el
    <script>;
  - el boton va en la barra, el panel FUERA de ella (la barra recorta lo que sobresale),
    la ruta va detras del login y la sesion guarda su caducidad en CTX.
"""
import ast
import base64
import hashlib
import html
import json
import os
import re
import sys
import time
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
    CTX = types.SimpleNamespace(user=None, role=None, exp=None)
    ns = {"html": html, "hashlib": hashlib, "re": re, "base64": base64, "time": time, "CTX": CTX,
          "buscar_usuario": lambda u: next((r for r in USUARIOS if r.get("user") == u), None)}
    cargar({"_ROL_TXT", "_AV_COLORS", "_iniciales", "_avatar", "_mu_ic", "_MU_CUENTA", "_MU_CLAVE",
            "_MU_SALIR", "_MU_JS", "_menu_usuario", "foto_de"}, ns)
    menu, foto_de = ns["_menu_usuario"], ns["foto_de"]

    b, p = menu()
    check("sin sesion: el Salir de siempre y sin menu", 'href="/logout"' in b and "Salir" in b and p == "", (b, p))

    USUARIOS.append({"user": "op1", "role": "operador", "nombre": "Ana Perez"})
    CTX.user, CTX.role, CTX.exp = "op1", "operador", time.time() + 3 * 3600 + 120
    b, p = menu()
    check("boton: iniciales, nombre y flecha", ">AP<" in b and "Ana Perez" in b and "&#9662;" in b and 'id="ubtn"' in b, b)
    check("panel: nombre y rol", "Ana Perez" in p and "Operador" in p, p)
    check("  Mi cuenta -> /ajustes#cuenta", 'href="/ajustes#cuenta">' in p and "Mi cuenta" in p, "")
    check("  Cambiar contrasena -> /ajustes#clave", 'href="/ajustes#clave">' in p and "Cambiar contrase&ntilde;a" in p, "")
    check("  Cerrar sesion -> /logout", re.search(r'href="/logout"[^>]*>.*?Cerrar sesi&oacute;n', p) is not None, "")
    m = re.search(r'id="ureloj" data-resta="(\d+)"', p)
    check("  Desconectar en: con lo que le queda a la sesion", m and 3 * 3600 + 100 <= int(m.group(1)) <= 3 * 3600 + 120, m and m.group(1))
    check("  el panel empieza cerrado", 'id="umenu" role="menu" hidden' in p, "")
    CTX.exp = None
    check("sin caducidad conocida no hay reloj (no manda al login)", 'id="ureloj"' not in menu()[1], "")
    CTX.exp = time.time() + 600

    png = base64.b64encode(b"\x89PNG\r\n\x1a\nfalso").decode()
    USUARIOS[0]["avatar"] = "data:image/png;base64," + png
    b1, p1 = menu()
    check("con foto: va por /mi-foto?v=, no incrustada", "/mi-foto?v=" in b1 and "base64" not in b1 + p1, b1)
    USUARIOS[0]["avatar"] = "data:image/png;base64," + base64.b64encode(b"\x89PNG otra").decode()
    v1 = re.search(r"v=(\w+)", b1).group(1); v2 = re.search(r"v=(\w+)", menu()[0]).group(1)
    check("  la huella cambia al cambiar la foto", v1 != v2, (v1, v2))

    USUARIOS[0]["nombre"] = '<script>alert(1)</script>'
    check("el nombre se escapa", "<script>alert" not in "".join(menu()), "")
    USUARIOS[0]["nombre"] = ""
    check("sin nombre: sale el usuario", ">op1<" in menu()[0], "")

    tipo, datos = foto_de("op1")
    check("/mi-foto: tipo y bytes de la foto del que la pide", tipo == "image/png" and datos == b"\x89PNG otra", (tipo, datos))
    check("  de un usuario que no existe: nada", foto_de("nadie") is None, "")
    check("  sin sesion: nada", foto_de(None) is None, "")
    USUARIOS[0]["avatar"] = "data:text/html;base64," + base64.b64encode(b"<script>").decode()
    check("  lo que no es imagen no se sirve", foto_de("op1") is None, "")

    # ---- Ajustes: #cuenta / #clave ----
    pp = DASH[DASH.index("def perfil_page("):DASH.index("def exclusiones_page(")]
    check("Ajustes atiende #cuenta y #clave (al cargar y al cambiar el #)",
          "_cuenta(location.hash.slice(1))" in pp and "hashchange" in pp, "")
    check("  lectura/operador: su tarjeta Perfil; admin: SU fila de Usuarios",
          "openm('perfil')" in pp and "abrirEdit(bs[k])" in pp and "data-user')===_YO" in pp, "")
    check("  la ventana de editar dice de quien es y avisa si falta nombre/correo (vacio en los datos, no fallo)",
          "<h3 id=etit>Editar usuario</h3>" in pp and "'Editar usuario: '+_u" in pp
          and "placeholder='Sin nombre guardado'" in pp and "placeholder='Sin correo guardado'" in pp, "")
    yo_js = re.search(r'"var _YO=" \+ (.+?) \+ ";"', pp).group(1)
    raro = "a</script><script>alert(1)//"
    salida = eval(yo_js, {"json": json, "yo": raro})
    check("  el usuario que va al JS no puede cerrar el <script>", "</" not in salida and json.loads(salida) == raro, salida)

    # ---- donde va ----
    check("el boton en la barra y el panel fuera de ella",
          "+ _ubtn + '</div></div>' + _upanel +" in DASH, "")
    i_ruta = DASH.index('if path == "/mi-foto":')
    i_get = DASH.rindex("def do_GET", 0, i_ruta)
    i_auth = DASH.index("if not self._auth_ok():", i_get)   # la puerta, no el /login de antes
    check("/mi-foto va detras del login", i_auth < i_ruta, (i_auth, i_ruta))
    check("la sesion deja su caducidad en CTX", 'CTX.exp = s.get("exp")' in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
