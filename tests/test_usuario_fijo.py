# -*- coding: utf-8 -*-
"""El usuario de entrar no se cambia nunca; de una cuenta se cambia la clave (o se elimina).

De donde sale: un admin edito su cuenta, cambio el "Nombre" y la clave, e intento entrar
con el nombre nuevo. No pudo: el "Nombre" es solo el que se muestra (arriba a la derecha
y en la tabla) y para entrar seguia valiendo "admin". Parecia que la clave no se habia
cambiado, y acabo creando otro usuario.

Lo que se protege (ejecutando el _post_perfil REAL con los usuarios en memoria):
  - editar cambia nombre a mostrar, correo, rol y clave, y NUNCA el usuario;
  - la clave nueva vale con el usuario de siempre y la vieja ya no; el nombre a mostrar
    no sirve para entrar;
  - un formulario que intente renombrar se rechaza entero (ni la clave cambia a medias);
  - el aviso al cambiar la clave dice con que usuario se entra;
  - la ventana Editar ensena el usuario sin campo con nombre (no viaja en el formulario)
    y lo rellena al abrirse; el menu de arriba ensena el usuario debajo del nombre;
  - la Documentacion lo explica.
"""
import ast
import hashlib
import html
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


def fuente(nombre):
    for n in ast.walk(ARBOL):
        if isinstance(n, ast.FunctionDef) and n.name == nombre:
            return ast.get_source_segment(DASH, n)
    raise KeyError(nombre)


def main():
    US = []
    BIT = []
    CTX = types.SimpleNamespace(user="admin", role="admin", ip="192.0.2.10")
    ns = {"CTX": CTX, "time": time, "re": re, "html": html, "hashlib": hashlib,
          "ROLES": ("admin", "operador", "lectura"),
          "cargar_usuarios": lambda: [dict(r) for r in US],
          "bitacora": lambda *a, **k: BIT.append(a),
          "perfil_page": lambda msg="", ok=True: {"msg": msg, "ok": ok},
          "SESSIONS": {}, "_guardar_sesiones": lambda: None}

    def guardar(lst):
        US[:] = [dict(r) for r in lst]
    ns["guardar_usuarios"] = guardar
    # el hash real del panel (PBKDF2 con sal) y la verificacion real del login
    for f in ("_hash_pw", "buscar_usuario", "verificar_login"):
        exec(fuente(f), ns)
    ns["secrets"] = __import__("secrets")
    exec(fuente("_post_perfil").replace("\n    ", "\n").lstrip(), ns)
    post = ns["_post_perfil"]

    class Yo(object):
        def _admin(self):
            return True

        def _deny(self):
            return {"msg": "denegado", "ok": False}

        def _html(self, x, *a):
            return x

        def _redirect(self, *a, **k):
            return {"redirect": a}

        def _sid(self):
            return ""

        def _client_ip(self):
            return "192.0.2.10"

    h = Yo()
    salt, hs = ns["_hash_pw"]("clave-vieja")
    US.append({"user": "admin", "salt": salt, "hash": hs, "role": "admin", "nombre": "", "correo": ""})
    vl = ns["verificar_login"]

    def q(**kw):
        return {k: [v] for k, v in kw.items()}

    r = post(h, q(accion="edit_user", user="admin", nombre="Manuel", correo="a@example.com",
                  role="admin", npass="clave-nueva-1"))
    check("editar: guarda nombre a mostrar, correo y clave", r["ok"] and US[0]["nombre"] == "Manuel"
          and US[0]["correo"] == "a@example.com", r)
    check("  y el usuario sigue siendo el mismo", [u["user"] for u in US] == ["admin"], US)
    check("  la clave nueva vale con el usuario de siempre", vl("admin", "clave-nueva-1") == "admin", "")
    check("  la vieja ya no", vl("admin", "clave-vieja") is None, "")
    check("  el nombre a mostrar no sirve para entrar", vl("Manuel", "clave-nueva-1") is None, "")
    check("  el aviso dice con que usuario se entra", "'admin'" in r["msg"] and "no sirve para entrar" in r["msg"], r["msg"])

    antes = dict(US[0])
    for campo in ("nuser", "usuario", "new_user"):
        r = post(h, q(accion="edit_user", user="admin", nombre="Otro", correo="", role="admin",
                      npass="clave-nueva-2", **{campo: "manuel"}))
        check("renombrar (campo %s): se rechaza" % campo, not r["ok"] and "no se puede cambiar" in r["msg"], r)
        check("  entero: ni usuario, ni nombre, ni clave cambian", US == [antes], US)
    r = post(h, q(accion="edit_user", user="admin", nuser="admin", nombre="Manuel", correo="", role="admin", npass=""))
    check("un formulario que manda el MISMO usuario se acepta", r["ok"] and US[0]["user"] == "admin", r)
    check("sin clave nueva, la clave no cambia", vl("admin", "clave-nueva-1") == "admin", "")

    # ---- la interfaz ----
    m = re.search(r'<div class=modal><div class=mhead><h3 id=etit>.*?</form>', DASH, re.S)
    ed = m.group(0) if m else ""
    usr = re.search(r'<input type=text id=eusr ([^>]*)>', ed)
    check("ventana Editar: el usuario se ve, de solo lectura y sin name (no viaja)",
          usr and "readonly" in usr.group(1) and "name=" not in usr.group(1), usr and usr.group(0))
    check("  y no hay ningun campo para escribir otro usuario",
          not re.search(r"name=(nuser|usuario|new_user)\b", ed), "")
    check("  el campo Nombre se llama 'Nombre a mostrar'", "<label>Nombre a mostrar</label><input type=text name=nombre id=en>" in ed, "")
    check("  al abrir, se rellena con el usuario de la fila",
          "document.getElementById('eusr').value=_u;" in fuente("perfil_page") or "document.getElementById('eusr').value=_u;" in DASH, "")
    check("ventana Nuevo: avisa que el usuario no se puede cambiar despues",
          "no se \"\n            \"puede cambiar despues" in DASH or "no se puede cambiar despues" in DASH.replace('"\n            "', ""), "")

    USERS2 = [{"user": "admin", "role": "admin", "nombre": "Manuel"}]
    ns2 = {"html": html, "hashlib": hashlib, "re": re, "time": time,
           "CTX": types.SimpleNamespace(user="admin", role="admin", exp=None),
           "buscar_usuario": lambda u: next((x for x in USERS2 if x["user"] == u), None)}
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("_iniciales", "_avatar", "_mu_ic", "_menu_usuario"):
            exec(ast.get_source_segment(DASH, n), ns2)
        elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in
                                                ("_ROL_TXT", "_AV_COLORS", "_MU_CUENTA", "_MU_CLAVE", "_MU_SALIR", "_MU_JS")
                                                for t in n.targets):
            exec(ast.get_source_segment(DASH, n), ns2)
    _b, p = ns2["_menu_usuario"]()
    check("menu de arriba: el nombre y, debajo, el usuario con el que se entra",
          'class="uhn">Manuel<' in p and "Usuario: admin" in p, p[:400])

    check("Documentacion: el usuario no se cambia nunca", "<b>El usuario no se cambia nunca</b>" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
