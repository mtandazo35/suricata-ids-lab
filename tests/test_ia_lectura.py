# -*- coding: utf-8 -*-
"""La lectura con IA: que no se lleve datos del abonado y que si falla no estorbe.

Dos cosas que no pueden salir mal, y por motivos distintos:

  - **No sale ni una IP.** La IA no necesita saber QUIEN es para decir QUE es. Una IP de
    abonado identifica a una persona real y, una vez enviada a un tercero, ya salio: no
    hay forma de recogerla. Por eso no basta con "no la metemos": se comprueba sobre el
    JSON ya serializado, que es lo que de verdad viaja.
  - **Si falla, no se nota.** Esta es la pagina donde se decide cortarle el internet a un
    abonado. Un extra que explica no puede dejarla en blanco porque Groq tarde, devuelva
    basura o se acabe la cuota: en todos esos casos la ficha tiene que verse como siempre.
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

PIEZAS = ("GROQ_URL", "IA_CACHE", "IA_ESTADO", "IA_CUOTA", "IA_TIMEOUT", "IA_CACHE_MAX",
          "_IA_LOCK", "_RE_IP", "IA_SISTEMA", "ia_activa", "_ia_estado",
          "_ia_guardar_estado", "ia_restantes", "ia_datos", "_ia_huella", "_ia_cache",
          "_ia_guardar_cache", "ia_preguntar")

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
    def __init__(self, payload):
        self._p = payload

    def read(self):
        return json.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def entorno(tmp, contenido=None, clave="k", modelo="m-1", fallo=None):
    """El panel con un Groq de mentira. `contenido` es lo que devuelve el modelo."""
    visto = {}

    def _urlopen(req, timeout=0):
        visto["url"] = req.url
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
    ns["IA_CACHE"] = os.path.join(tmp, "ia-cache.json")
    ns["IA_ESTADO"] = os.path.join(tmp, "ia-estado.json")
    ns["_visto"] = visto
    return ns


# Un candidato con IPs por todas partes, incluida una dentro del texto de la firma.
CAND = {
    "ip": "10.8.0.199", "banda": "MEDIO", "riesgo": 67,
    "total_alertas": 382, "destinos": 3, "puertos": 2,
    "evidencias": ["4 firmas DNS distintas", "patron compartido con otros CPE (campana)"],
    "reputacion": [{"fuente": "urlhaus", "categoria": "malware_download",
                    "cidr": "198.51.100.0/24", "ip": "198.51.100.7"}],
    "pruebas": [
        {"sid": "2014169", "rev": "4", "sig": "ET DNS Query for .su TLD",
         "rrname": "dontworry.su", "ts": 1790000000, "flow_id": "115559325752856"},
        {"sid": "2019876", "rev": "2", "sig": "ET MALWARE CnC checkin a 203.0.113.9",
         "dst": "198.51.100.7", "dport": 8080, "ts": 1790000300},
    ],
}

BUENA = json.dumps({"veredicto": "infectado",
                    "explicacion": "El equipo pregunta por un dominio de control.",
                    "accion": "Avisar al abonado y limpiar el equipo.",
                    "motivo_falso_positivo": ""})


def main():
    tmp = tempfile.mkdtemp()

    # =====================================================================================
    # Lo que viaja
    # =====================================================================================
    ns = entorno(tmp)
    datos = ns["ia_datos"](CAND)
    crudo = json.dumps(datos, ensure_ascii=False)

    # sobre el JSON serializado, que es lo que de verdad sale por el cable
    check("no viaja ninguna IP", not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", crudo),
          crudo)
    check("ni la del abonado", "10.8.0.199" not in crudo, crudo)
    check("ni la del destino", "198.51.100.7" not in crudo, crudo)
    # esta estaba DENTRO del texto de una firma: no basta con no copiar el campo dst
    check("ni una escondida dentro del texto de una firma",
          "203.0.113.9" not in crudo, crudo)
    check("ni un CIDR de la reputacion", "198.51.100.0" not in crudo, crudo)

    # y lo que si viaja, que es lo que describe el comportamiento
    check("si va el nombre de la firma", "ET DNS Query for .su TLD" in crudo, crudo)
    check("y el dominio consultado", "dontworry.su" in crudo, crudo)
    check("y el puerto de destino", 8080 in datos.get("puertos_destino", []), datos)
    check("y de que fuente viene la reputacion", "urlhaus" in crudo, crudo)
    check("y las evidencias independientes",
          "campana" in crudo and len(datos.get("evidencias_independientes") or []) == 2, datos)

    # nada que identifique al cliente
    for k in ("cliente", "nombre", "mac", "router", "abonado"):
        check("no se manda el campo '%s'" % k, k not in crudo.lower(), crudo)

    # =====================================================================================
    # Si falla, no estorba
    # =====================================================================================
    check("sin clave no se pregunta nada",
          entorno(tmp, BUENA, clave="")["ia_preguntar"](CAND) is None, "")
    check("sin modelo tampoco",
          entorno(tmp, BUENA, modelo="")["ia_preguntar"](CAND) is None, "")

    for nombre, exc in (("sin red", URLError("no hay ruta")),
                        ("si Groq devuelve error", HTTPError(500)),
                        ("si tarda demasiado", TimeoutError())):
        ns = entorno(tmp, fallo=exc)
        check("%s, se devuelve None y la ficha no cambia" % nombre,
              ns["ia_preguntar"](CAND) is None, "")

    ns = entorno(tmp, "esto no es json")
    check("una respuesta ilegible no revienta nada", ns["ia_preguntar"](CAND) is None, "")
    ns = entorno(tmp, json.dumps({"veredicto": "infectado", "explicacion": ""}))
    check("una respuesta vacia tampoco se da por buena",
          ns["ia_preguntar"](CAND) is None, "")

    # un CPE sin firmas ni dominios no da nada que leer: no se gasta una consulta
    ns = entorno(tmp, BUENA)
    check("sin evidencia que leer, ni se pregunta",
          ns["ia_preguntar"]({"pruebas": [], "evidencias": []}) is None
          and ns["_visto"].get("n") is None, ns["_visto"])

    # =====================================================================================
    # El caso bueno, la cache y la cuota
    # =====================================================================================
    d2 = tempfile.mkdtemp()
    ns = entorno(d2, BUENA)
    r = ns["ia_preguntar"](CAND)
    check("una respuesta buena se entiende", (r or {}).get("veredicto") == "infectado", r)
    check("y dice con que modelo se saco", (r or {}).get("modelo") == "m-1", r)
    check("la consulta va al endpoint de chat",
          ns["_visto"]["url"].endswith("/chat/completions"), ns["_visto"]["url"])
    check("y la clave no viaja en la URL", "k" not in ns["_visto"]["url"].split("//")[-1]
          .replace("api.groq.com", "").replace("/openai/v1/chat/completions", ""), "")

    # la misma evidencia no se vuelve a pagar
    ns2 = entorno(d2, BUENA)
    r2 = ns2["ia_preguntar"](CAND)
    check("la misma evidencia sale de la cache, sin otra consulta",
          r2 == r and ns2["_visto"].get("n") is None, ns2["_visto"])

    # cambiar de modelo SI tiene que volver a preguntar: la respuesta es de otro
    ns3 = entorno(d2, BUENA, modelo="m-2")
    ns3["ia_preguntar"](CAND)
    check("con otro modelo se vuelve a preguntar", ns3["_visto"].get("n") == 1,
          ns3["_visto"])

    # la cuota es un tope duro: un bucle no puede vaciar la cuenta
    d3 = tempfile.mkdtemp()
    ns = entorno(d3, BUENA)
    ns["_ia_guardar_estado"]({"dia": time.strftime("%Y-%m-%d"),
                              "gastadas": ns["IA_CUOTA"]})
    check("agotada la cuota del dia, no se pregunta mas",
          ns["ia_preguntar"](CAND) is None and ns["_visto"].get("n") is None, ns["_visto"])
    check("y se puede saber cuanto queda", ns["ia_restantes"]() == 0, "")

    # el intento se apunta ANTES de salir a la red: si no, un Groq que siempre falla
    # dejaria el contador a cero y reintentaria sin fin
    d4 = tempfile.mkdtemp()
    ns = entorno(d4, fallo=URLError("x"))
    ns["ia_preguntar"](CAND)
    check("un intento fallido tambien gasta cuota",
          ns["ia_restantes"]() == ns["IA_CUOTA"] - 1, ns["ia_restantes"]())

    # =====================================================================================
    # Lo que se le pide al modelo y lo que se hace con lo que devuelve
    # =====================================================================================
    check("se le pide castellano llano, para quien no es de redes",
          "NO es de redes" in DASH and "sin jerga" in DASH, "")
    check("y que no se invente lo que no esta en la evidencia",
          "No inventes datos" in DASH, "")
    # lo que devuelve el modelo es TEXTO para una persona: se escapa y no dispara nada
    _f = DASH[DASH.index("_ia = None"):DASH.index("_ia = None") + 2200]
    check("todo lo que devuelve el modelo se escapa antes de pintarlo",
          "esc(_ia.get('explicacion'" in _f and "esc(_ia.get('accion'" in _f, "")
    check("la ficha avisa de que es una opinion, no una medicion",
          "Es una opinion, no una medicion" in DASH, "")
    check("y de que la decision sigue siendo del operador",
          "el corte siguen" in DASH or "siguen siendo tuyos" in DASH, "")
    # si la lectura no sale, la fila no aparece: la ficha queda como antes de existir esto
    check("sin lectura, la fila ni se pinta",
          '(_row("Lectura de la IA", ia_html) if ia_html else "")' in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
