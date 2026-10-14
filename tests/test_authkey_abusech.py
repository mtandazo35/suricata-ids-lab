# -*- coding: utf-8 -*-
"""La Auth-Key de abuse.ch se valida de verdad.

Antes se «validaba» descargando el hostfile de URLhaus, que abuse.ch sirve SIN clave: cualquier
texto (hasta la clave de AbuseIPDB) salia «valida». Ahora se pregunta a la API de ThreatFox, que
con una clave mala responde 403 y query_status=unknown_auth_key. Aqui un servidor local hace de
abuse.ch: nada sale a internet.

  - clave mala (403 unknown_auth_key)            -> False
  - clave buena (no_result / ok)                 -> True
  - lo que devuelve el hostfile (texto, 200)     -> None, nunca True
  - sin red                                      -> None
  - vacia                                        -> False, sin llamar a nadie
"""
import ast
import http.server
import json
import os
import sys
import threading
import urllib.error
import urllib.request

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)
PIEZAS = ("ABUSECH_PRUEBA_URL", "_ABUSECH_MALA", "feeds_auth_probar")

ns = {"json": json, "urllib": urllib, "__name__": "authkey"}
for nodo in ARBOL.body:
    nombre = getattr(nodo, "name", None) or (
        nodo.targets[0].id if isinstance(nodo, ast.Assign) and isinstance(nodo.targets[0], ast.Name) else None)
    if nombre in PIEZAS:
        exec(compile(ast.Module(body=[nodo], type_ignores=[]), "dash", "exec"), ns)
faltan = [p for p in PIEZAS if p not in ns]
if faltan:
    print("FALLA no se encontraron en el panel:", faltan)
    sys.exit(1)

vistas = []


class AbuseCh(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        clave = self.headers.get("Auth-Key", "")
        cuerpo = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        vistas.append((self.path, clave, cuerpo))
        if clave == "hostfile":
            codigo, datos, tipo = 200, b"# abuse.ch URLhaus Host file\n127.0.0.1 malo.example\n", "text/plain"
        elif clave == "buena":
            codigo, datos, tipo = 200, json.dumps({"query_status": "no_result"}).encode(), "application/json"
        else:
            codigo, datos, tipo = 403, json.dumps({"query_status": "unknown_auth_key"}).encode(), "application/json"
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), AbuseCh)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ns["ABUSECH_PRUEBA_URL"] = "http://127.0.0.1:%d/api/v1/" % srv.server_address[1]
os.environ.pop("HTTP_PROXY", None); os.environ.pop("http_proxy", None)
os.environ["NO_PROXY"] = "127.0.0.1"

fallos = 0


def check(desc, cond, extra=""):
    global fallos
    print(("  OK   " if cond else " FALLA ") + desc + ("" if cond else "  -> " + str(extra)))
    if not cond:
        fallos += 1


probar = ns["feeds_auth_probar"]
r = probar("clave-de-abuseipdb-0123456789")
check("una clave que no es de abuse.ch se rechaza", r[0] is False and "unknown_auth_key" in r[1], r)
r = probar("buena")
check("una clave que abuse.ch acepta es valida", r == (True, "valida"), r)
r = probar("hostfile")
check("una respuesta que no es de la API (texto del hostfile) NO cuenta como valida", r[0] is None, r)
check("la clave va en la cabecera Auth-Key de una consulta a la API",
      vistas and vistas[-1][1] == "hostfile" and b"search_ioc" in vistas[-1][2], vistas[-1:])
n = len(vistas)
check("vacia: no valida y no se llama a nadie", probar("  ") == (False, "vacia") and len(vistas) == n)
srv.shutdown(); srv.server_close()
ns["ABUSECH_PRUEBA_URL"] = "http://127.0.0.1:9/api/v1/"
r = probar("buena")
check("sin red: no se puede comprobar (ni valida ni invalida)", r[0] is None, r)

print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
sys.exit(1 if fallos else 0)
