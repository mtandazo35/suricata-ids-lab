# -*- coding: utf-8 -*-
"""/cuarentena/quitar-varios (respaldo sin JS) con dobles."""
import ast, ipaddress, os, secrets, sys, time, urllib.parse as _up, textwrap
_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
CODIGO = open(os.path.join(_DIR, "ruta_masivo.py"), encoding="utf-8").read()

# el aviso viaja como CODIGO de un solo uso (/cuarentena?msg=<codigo>): se usan las
# funciones reales del panel para guardarlo y para leerlo
_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = open(os.path.join(_RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_DASH = _SRC[_SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'"):].split("\n", 1)[1]
_DASH = _DASH.split("\nDASH\n", 1)[0]
AV = {"time": time, "secrets": secrets}
for _n in ast.parse(_DASH).body:
    _nom = getattr(_n, "name", None) or (getattr(_n.targets[0], "id", "")
                                         if isinstance(_n, ast.Assign) and _n.targets else "")
    if _nom in ("_REP_AVISOS", "_REP_AVISOS_TTL", "rep_aviso_guardar", "rep_aviso_tomar",
                "rep_aviso_url", "cuar_aviso_url"):
        exec(ast.get_source_segment(_DASH, _n), AV)

def correr(sels, operador=True, fallan=(), caido=False, estado=None, intentos=None,
           tras_quitar=None):
    estado = estado if estado is not None else {
        "cuar": {"10.6.1.89": {}, "10.6.2.82": {}, "10.6.0.208": {}},
        "dns":  {"198.51.100.5": {}}}
    class Self:
        def _operador(self): return operador
        def _deny(self): return ("DENY", 403)
        def _redirect(self, url): return ("REDIR", url)
    def remove(ip, lista=None, router=None):
        if intentos is not None: intentos.append(ip)
        if caido: return (False, "no hay conexion con el router")
        return (False, "el router rechazo") if ip in fallan else (True, "")
    def quitar(ips, path="cuar"):
        # simula que MIENTRAS se hablaba con el router, el hilo de fondo anoto un CPE nuevo
        if tras_quitar: tras_quitar()
        return [i for i in ips if estado[path].pop(i, None) is not None]
    ns = {"self": Self(), "q": {"sel": sels}, "_up": _up, "ipaddress": ipaddress,
          "MK_SENT": "cuar", "MK_SENT_DNS": "dns",
          "cargar_mk": lambda: {"LIST_DNS": "lista-dns"},
          "cargar_enviados": lambda path="cuar": estado[path],
          "quitar_enviados": quitar,
          "mk_remove": remove, "mk_log": lambda *a: None,
          "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k,
          "rid_de": lambda k: k.split("|", 1)[0] if "|" in k else "",
          "router_de_clave": lambda k: {"id": (k.split("|", 1)[0] if "|" in k else "r1")},
          "cargar_mk_de": lambda r: {"LIST_DNS": "lista-dns"},
          "_suf_nodo": lambda k: "",
          "CTX": type("C", (), {"user": "ana"})(),
          "cuar_aviso_url": AV.get("cuar_aviso_url")}
    exec(compile("def _f():\n" + textwrap.indent(CODIGO, "    "), "<r>", "exec"), ns)
    return ns["_f"](), estado

_LEIDOS = {}
def msg(r):
    """El texto que vera el usuario: la URL lleva un codigo y el panel lo traduce. El
    codigo es de un solo uso: se recuerda lo leido para poder mirarlo varias veces."""
    assert r[1].startswith("/cuarentena?msg="), r
    cod = _up.unquote(r[1].split("msg=", 1)[1])
    if cod not in _LEIDOS:
        _LEIDOS[cod] = AV["rep_aviso_tomar"](cod)[0]
    return _LEIDOS[cod]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1

r, estado = correr(["cuar|10.6.1.89", "dns|198.51.100.5", "cuar|10.6.2.82"])
check("la URL del redirect no lleva el texto, solo un codigo",
      "entrada" not in _up.unquote(r[1]) and " " not in _up.unquote(r[1]), r[1])
check("quita de ambas listas y lo resume", msg(r) == "3 entrada(s) quitada(s)", msg(r))
check("cada una sale de SU registro",
      estado["cuar"] == {"10.6.0.208": {}} and estado["dns"] == {}, estado)

r, estado = correr(["cuar|10.6.1.89", "cuar|10.6.2.82"], fallan={"10.6.2.82"})
check("informa cual fallo y por que", "10.6.2.82 (el router rechazo)" in msg(r), msg(r))
check("la que fallo sigue en el registro", "10.6.2.82" in estado["cuar"], estado["cuar"])

# HALLAZGO: con el router caido no debe esperar el timeout de las 500
intentos = []
r, _ = correr(["cuar|10.6.1.89", "cuar|10.6.2.82", "cuar|10.6.0.208"], caido=True, intentos=intentos)
check("router caido: corta en la primera y no intenta las demas", len(intentos) == 1, intentos)
check("y lo dice claramente", "no responde" in msg(r), msg(r))

# HALLAZGO: el tope de 500 no debe descartar en silencio
r, _ = correr(["cuar|10.6.1.89"] * 600)
check("avisa cuantas quedaron fuera del tope", "Quedan 100 sin procesar" in msg(r), msg(r))

# HALLAZGO: no dar por quitada una IP que no estaba en esa lista
intentos = []
r, estado = correr(["cuar|198.51.100.5"], intentos=intentos)   # esa vive en la lista DNS
check("no da falso exito por la lista equivocada",
      msg(r).startswith("0 entrada(s)") and "no esta en esa lista" in msg(r), msg(r))
check("ni siquiera llama al router", not intentos, intentos)

# HALLAZGO: no pisar lo que otro hilo escribio mientras hablabamos con el router
estado = {"cuar": {"10.6.1.89": {}}, "dns": {}}
def intruso():
    estado["cuar"]["10.7.7.7"] = {"por": "politica-rapida"}   # el barrido rapido, a mitad
r, estado = correr(["cuar|10.6.1.89"], estado=estado, tras_quitar=intruso)
check("conserva el CPE que el hilo de fondo anoto mientras tanto",
      "10.7.7.7" in estado["cuar"] and "10.6.1.89" not in estado["cuar"], estado["cuar"])

r, _ = correr(["cuar|10.6.1.89"], operador=False)
check("sin permiso no hace nada", r == ("DENY", 403), r)
r, estado = correr([])
check("sin seleccion avisa y no toca nada", msg(r) == "No seleccionaste ninguna IP", msg(r))

print("\n" + ("TODO OK" if not fallos else f"{fallos} fallo(s)"))
raise SystemExit(1 if fallos else 0)
