# -*- coding: utf-8 -*-
"""Un formulario de OTRA web no puede mandar acciones al panel (CSRF).

La cookie de sesion va con SameSite=Strict, pero sin usuarios (modo sin-auth, tras VPN o
proxy) _auth_ok() y _admin() dicen que si a todo: cualquier pagina abierta en el navegador
del operador podia hacer un POST a /vpn/sensor-aplicar y lanzar el instalador como root.

Lo que se protege, ejecutando el despacho REAL de POST de la clase del panel (do_POST y lo
que llama), con el resto de dobles:
  - mismo origen (lo que hacen el login y los fetch del propio panel): pasa;
  - Origin de otro sitio: 403 y la accion NO se ejecuta; Referer de otro sitio sin Origin:
    igual; Origin "null" (iframe con sandbox): igual; mismo nombre y otro puerto: igual;
  - sin Origin ni Referer (curl, scripts): pasa;
  - detras de un proxy: Host sin puerto (nginx manda $host) o X-Forwarded-Host: pasa.
"""
import ast
import os
import sys
import traceback
import types
import urllib.parse

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)[:400]))
    if not c:
        fallos += 1


def clase():
    """do_POST y lo que llama, de la clase H real; _post (las acciones) es un doble que
    apunta si llego a ejecutarse."""
    import html
    ns = {"urllib": urllib, "sys": sys, "traceback": traceback, "html": html,
          "bitacora": lambda *a, **k: None}
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("origen_ajeno", "_host_puerto"):
            exec(ast.get_source_segment(DASH, n), ns)
    cls = next(n for n in ARBOL.body if isinstance(n, ast.ClassDef) and n.name == "H")
    metodos = {}
    for m in cls.body:
        if isinstance(m, ast.FunctionDef) and m.name in ("do_POST", "_post_mismo_origen", "_seguro"):
            exec(compile(ast.Module(body=[m], type_ignores=[]), "<H.%s>" % m.name, "exec"), ns)
            metodos[m.name] = ns[m.name]
    return type("HPrueba", (object,), metodos)


H = clase()


class _Err(object):
    def write(self, _t):
        pass

    def flush(self):
        pass


def post(cabeceras, ruta="/vpn/sensor-aplicar"):
    p = H()
    p.path, p.command = ruta, "POST"
    p.headers = dict(cabeceras)
    p.close_connection = False
    p.ejecutado = []
    p.resp = []
    p._html = lambda s, code=200: p.resp.append(code)
    p._post = lambda: (p.ejecutado.append(ruta), p.resp.append(200))
    viejo = sys.stderr
    sys.stderr = _Err()
    try:
        p.do_POST()
    finally:
        sys.stderr = viejo
    return p


def main():
    panel = "192.0.2.10:5637"
    casos_ok = [
        ("mismo origen (fetch del propio panel)", {"Host": panel, "Origin": "http://192.0.2.10:5637"}),
        ("mismo origen solo con Referer", {"Host": panel, "Referer": "http://192.0.2.10:5637/ajustes#vpn"}),
        ("sin Origin ni Referer (curl, scripts)", {"Host": panel}),
        ("por la VPN", {"Host": "100.64.0.1:5637", "Origin": "http://100.64.0.1:5637"}),
        ("detras de un proxy HTTPS (Host sin puerto)", {"Host": "ids.example.com", "Origin": "https://ids.example.com"}),
        ("proxy en otro puerto que manda $host sin puerto",
         {"Host": "ids.example.com", "Origin": "https://ids.example.com:8443"}),
        ("proxy que reescribe Host pero manda X-Forwarded-Host",
         {"Host": "127.0.0.1:5637", "X-Forwarded-Host": "ids.example.com", "Origin": "https://ids.example.com"}),
        ("mayusculas en el nombre", {"Host": "IDS.example.com", "Origin": "https://ids.EXAMPLE.com"}),
    ]
    for nombre, cab in casos_ok:
        p = post(cab)
        check("pasa: %s" % nombre, p.ejecutado and p.resp == [200], (p.resp, cab))
    casos_mal = [
        ("Origin de otro sitio", {"Host": panel, "Origin": "https://ataque.example.net"}),
        ("Referer de otro sitio (sin Origin)", {"Host": panel, "Referer": "https://ataque.example.net/x.html"}),
        ("Origin null (iframe con sandbox)", {"Host": panel, "Origin": "null"}),
        ("mismo nombre, otro puerto", {"Host": panel, "Origin": "http://192.0.2.10:8080"}),
        ("otro sitio que se parece", {"Host": "ids.example.com", "Origin": "https://ids.example.com.ataque.example.net"}),
        ("esquema raro", {"Host": panel, "Origin": "file://"}),
        ("Origin ajeno aunque el Referer sea el bueno",
         {"Host": panel, "Origin": "https://ataque.example.net", "Referer": "http://192.0.2.10:5637/"}),
    ]
    for nombre, cab in casos_mal:
        p = post(cab)
        check("403 y NO se ejecuta: %s" % nombre, not p.ejecutado and p.resp == [403], (p.resp, cab))
    p = post({"Host": panel, "Origin": "https://ataque.example.net"}, ruta="/login")
    check("tambien el login (no se puede forzar a entrar con otra cuenta)", not p.ejecutado and p.resp == [403], p.resp)
    p = post({"Host": panel, "Origin": "https://ataque.example.net"})
    check("el rechazo cierra la conexion (el cuerpo no se leyo)", p.close_connection is True, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
