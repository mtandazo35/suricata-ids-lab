# -*- coding: utf-8 -*-
"""/cuarentena/quitar-uno con dobles (sin MikroTik ni disco)."""
import ipaddress, os, sys, textwrap
_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
CODIGO = open(os.path.join(_DIR, "ruta_uno.py"), encoding="utf-8").read()

def correr(sel, operador=True, fallan=(), estado=None, logs=None):
    estado = estado if estado is not None else {"cuar": {"10.6.1.89": {}}, "dns": {"10.6.0.144": {}}}
    resp = {}
    class Self:
        def _operador(self): return operador
        def _json(self, obj, code=200):
            resp.update(obj); resp["_code"] = code; return obj
    def quitar(ips, path="cuar"):
        hechas = [i for i in ips if estado[path].pop(i, None) is not None]
        return hechas
    ns = {"self": Self(), "q": {"sel": [sel]}, "ipaddress": ipaddress,
          "MK_SENT": "cuar", "MK_SENT_DNS": "dns",
          "cargar_mk": lambda: {"LIST_DNS": "lista-dns"},
          "cargar_enviados": lambda path="cuar": estado[path],
          "quitar_enviados": quitar,
          "mk_remove": lambda ip, lista=None: (False, "sin respuesta del router") if ip in fallan else (True, ""),
          "mk_log": (lambda *a: logs.append(a)) if logs is not None else (lambda *a: None),
          "CTX": type("C", (), {"user": "ana"})()}
    exec(compile("def _f():\n" + textwrap.indent(CODIGO, "    "), "<r>", "exec"), ns)
    return ns["_f"](), resp, estado

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1

_, resp, estado = correr("cuar|10.6.1.89")
check("quita y responde ok", resp.get("ok") is True and "10.6.1.89" not in estado["cuar"], (resp, estado))

_, resp, estado = correr("dns|10.6.0.144")
check("una de DNS sale de SU registro", resp["ok"] and "10.6.0.144" not in estado["dns"], (resp, estado))

logs = []
_, resp, estado = correr("cuar|10.6.1.89", fallan={"10.6.1.89"}, logs=logs)
check("router caido: ok=false con el motivo", resp["ok"] is False and "sin respuesta" in resp["err"], resp)
check("la IP SIGUE en el registro para reintentar", "10.6.1.89" in estado["cuar"], estado["cuar"])
check("queda registrado como error", any("ERROR-QUITAR" in str(l) for l in logs), logs)

_, resp, _ = correr("cuar|no-es-ip")
check("IP manipulada: error claro", resp["ok"] is False and resp["err"] == "IP invalida", resp)

# HALLAZGO de la auditoria: pedir una IP por la lista equivocada daba un visto bueno falso
logs = []
_, resp, estado = correr("cuar|10.6.0.144", logs=logs)   # esa IP vive en la lista DNS
check("pedirla por la lista equivocada NO da falso exito",
      resp["ok"] is False and "no esta en esa lista" in resp["err"], resp)
check("y no se toca el router ni el registro",
      "10.6.0.144" in estado["dns"] and not logs, (estado, logs))

_, resp, estado = correr("cuar|10.6.1.89", operador=False)
check("sin permiso: 403 y sin tocar nada", resp.get("_code") == 403 and "10.6.1.89" in estado["cuar"], resp)

print("\n" + ("TODO OK" if not fallos else f"{fallos} fallo(s)"))
raise SystemExit(1 if fallos else 0)
