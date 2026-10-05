# -*- coding: utf-8 -*-
"""Que bloquear para salir de las listas negras.

La idea del apartado: salir de una lista negra empieza por dejar de abusar. Asi que
primero se ensena por donde sale el abuso MEDIDO, y la IA ordena y explica.

Lo que se protege, en orden de importancia:

  - **La IA no inventa puertos.** Lo que devuelve el modelo se filtra contra lo medido.
    Un puerto inventado aqui no es un detalle cosmetico: es una linea de firewall que
    alguien va a copiar y pegar, y cortaria trafico de abonados que no han hecho nada.
  - **Nada de lo medido se pierde** porque el modelo no lo nombre: lo que no ordena va
    detras, no desaparece.
  - **Sin IA el apartado sigue sirviendo.** Los puertos, los numeros y las reglas salen
    de la medicion; la IA solo pone el orden y la explicacion.
  - **Las reglas no cortan a toda la red** por su cuenta: van contra los abonados ya
    fichados. Cerrar el correo saliente a todo el mundo es una decision de negocio.
"""
import ast
import json
import os
import re
import sys
import tempfile
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("PUERTOS_NOMBRE", "perfil_abuso", "reglas_puertos", "IA_PLAN_SISTEMA",
          "ia_plan_bloqueo", "ia_activa", "_RE_IP", "_ia_huella", "_ia_cache",
          "_ia_guardar_cache", "_ia_estado", "_ia_guardar_estado", "_ia_apuntar",
          "ia_restantes", "IA_CACHE", "IA_ESTADO", "IA_CUOTA", "IA_TIMEOUT",
          "IA_CACHE_MAX", "_IA_LOCK", "GROQ_URL", "ros_lista", "_RE_ROS_RARO")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class HTTPError(Exception):
    def __init__(self, code=500):
        self.code = code


class URLError(Exception):
    pass


class _Resp(object):
    def __init__(self, p):
        self._p = p

    def read(self):
        return json.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def entorno(tmp, contenido=None, clave="k", modelo="m-1", fallo=None):
    visto = {}

    def _urlopen(req, timeout=0):
        visto["cuerpo"] = (req.data or b"").decode("utf-8")
        visto["n"] = visto.get("n", 0) + 1
        if fallo is not None:
            raise fallo
        return _Resp({"choices": [{"message": {"content": contenido}}]})

    class _Req(object):
        def __init__(self, url, data=None, headers=None, **k):
            self.url, self.data, self.headers = url, data, headers or {}

    urllib_falso = type("U", (), {
        "request": type("R", (), {"Request": _Req, "urlopen": staticmethod(_urlopen)}),
        "error": type("E", (), {"HTTPError": HTTPError, "URLError": URLError}),
    })
    ns = {"json": json, "os": os, "re": re, "time": time, "sys": sys,
          "threading": threading, "urllib": urllib_falso,
          "_hashlib": __import__("hashlib"), "TimeoutError": TimeoutError,
          "groq_key": lambda: clave, "groq_modelo": lambda: modelo}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["IA_CACHE"] = os.path.join(tmp, "c.json")
    ns["IA_ESTADO"] = os.path.join(tmp, "e.json")
    ns["_visto"] = visto
    return ns


def dias_falsos():
    """Tres dias con abuso por 25/tcp (mayoria), 22/tcp y 3389/tcp."""
    d = {}
    for i in range(1, 4):
        f = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        d[f] = {"sal": 100, "puertos": {"25/tcp": 70, "22/tcp": 20, "3389/tcp": 10},
                "cats": {"spam": 70, "escaneo": 30}}
    return d


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # =====================================================================================
    # La medicion
    # =====================================================================================
    p = ns["perfil_abuso"](dias_falsos())
    check("se suman los dias y sale el abuso total", p["alertas"] == 300, p["alertas"])
    check("los puertos van del que mas pesa al que menos",
          [x["puerto"] for x in p["puertos"]] == ["25/tcp", "22/tcp", "3389/tcp"], p["puertos"])
    check("con su peso en porcentaje", p["puertos"][0]["pct"] == 70.0, p["puertos"][0])
    # el numero de puerto solo no le dice nada a quien no es de redes
    check("y diciendo QUE es cada puerto, no solo el numero",
          "correo saliente" in p["puertos"][0]["que_es"], p["puertos"][0])
    # tres dias de 70: lo que importa es que se ACUMULEN a lo largo del periodo, no
    # que se quede con el ultimo dia
    check("las categorias se suman a lo largo de los dias",
          dict(p["categorias"]).get("spam") == 210, p["categorias"])
    check("sin datos no revienta", ns["perfil_abuso"]({})["puertos"] == [], "")

    # =====================================================================================
    # LO IMPORTANTE: la IA no puede inventarse un puerto
    # =====================================================================================
    # Un puerto inventado aqui acaba en una regla de firewall que alguien pega.
    inventa = json.dumps({
        "orden": ["25/tcp", "9999/tcp", "443/tcp", "22/tcp"],
        "motivo": {"25/tcp": "es por donde sale el spam",
                   "9999/tcp": "esto me lo acabo de inventar"},
        "resumen": "Cierra primero el correo saliente."})
    ns = entorno(tmp, inventa)
    plan = ns["ia_plan_bloqueo"](p, ["spamhaus"])
    check("un puerto que no se midio NO entra en el plan",
          "9999/tcp" not in plan["orden"] and "443/tcp" not in plan["orden"], plan["orden"])
    check("y tampoco su justificacion", "9999/tcp" not in plan["motivo"], plan["motivo"])
    check("se deja constancia de lo que se descarto",
          sorted(plan["inventados"]) == ["443/tcp", "9999/tcp"], plan["inventados"])
    check("el orden que si vale se respeta", plan["orden"][0] == "25/tcp", plan["orden"])
    # lo medido que el modelo no nombro no puede desaparecer: sigue siendo abuso real
    check("lo medido que el modelo no ordeno va detras, no se pierde",
          set(plan["orden"]) == {"25/tcp", "22/tcp", "3389/tcp"}, plan["orden"])
    check("sin repetidos", len(plan["orden"]) == len(set(plan["orden"])), plan["orden"])

    # y al modelo no se le mandan IPs, como en el resto
    check("al modelo no se le manda ninguna IP",
          not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", ns["_visto"]["cuerpo"]),
          ns["_visto"]["cuerpo"][:200])
    check("y se le prohibe inventar", "No inventes puertos" in ns["IA_PLAN_SISTEMA"], "")
    check("se le pide castellano llano", "NO es de redes" in ns["IA_PLAN_SISTEMA"], "")

    # =====================================================================================
    # Sin IA, el apartado sigue sirviendo
    # =====================================================================================
    check("sin clave no hay plan, y eso no es un error",
          entorno(tmp, inventa, clave="")["ia_plan_bloqueo"](p, []) is None, "")
    check("sin puertos medidos ni se pregunta",
          ns["ia_plan_bloqueo"]({"puertos": []}, []) is None, "")
    for nom, exc in (("sin red", URLError("x")), ("con error de Groq", HTTPError(500))):
        n2 = entorno(tempfile.mkdtemp(), fallo=exc)
        check("%s se devuelve None, no una lista a medias" % nom,
              n2["ia_plan_bloqueo"](p, []) is None, "")
    n2 = entorno(tempfile.mkdtemp(), "no es json")
    check("una respuesta ilegible tampoco da un plan", n2["ia_plan_bloqueo"](p, []) is None, "")

    # =====================================================================================
    # Las reglas que se pegan
    # =====================================================================================
    r = ns["reglas_puertos"](["25/tcp", "22/tcp"], "Cliente Virus")
    check("sale una linea por puerto", r.count("add chain=forward") == 2, r)
    check("contra los abonados fichados, no contra toda la red",
          'src-address-list="Cliente Virus"' in r, r)
    # el nombre lleva espacio: sin comillas RouterOS corta el comando
    check("con el nombre de la lista entrecomillado",
          "src-address-list=Cliente Virus" not in r, r)
    check("el comentario dice que es el puerto, no solo el numero",
          "correo saliente" in r, r)
    check("un puerto con basura se ignora en vez de generar una regla rota",
          ns["reglas_puertos"](["no-es-un-puerto", "25/tcp"], "L").count("add ") == 1,
          ns["reglas_puertos"](["no-es-un-puerto", "25/tcp"], "L"))
    check("un protocolo raro tampoco pasa",
          ns["reglas_puertos"](["25/sctp"], "L") == "", "")
    check("sin puertos no se inventa una regla vacia", ns["reglas_puertos"]([], "L") == "", "")

    # =====================================================================================
    # Y lo que la pantalla promete
    # =====================================================================================
    check("el apartado dice que salir empieza por dejar de abusar",
          "empieza por dejar de abusar" in DASH, "")
    check("y avisa de que la IA opina sobre lo medido, no mide",
          "Es una opinion sobre lo medido" in DASH, "")
    check("y de que el corte general es decision de negocio",
          "decision de negocio" in DASH, "")
    check("enlaza con los dias limpios, que es lo que habilita pedir la salida",
          "los dias limpios empiezan a contar" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
