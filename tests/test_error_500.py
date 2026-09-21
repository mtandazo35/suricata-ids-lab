# -*- coding: utf-8 -*-
"""Una pagina que revienta no debe tumbar la conexion.

Sin red de seguridad, una excepcion mataba el hilo y la conexion se cerraba sin
respuesta. Detras de un proxy inverso (nginx/openresty) eso le llega al usuario como
un "502 Bad Gateway" pelado: no dice que fallo, ni donde mirar, ni si el panel entero
esta caido. Aqui se comprueba que en su lugar sale un 500 explicado y que el fallo
queda anotado.
"""
import ast
import io
import os
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


def cargar_seguro(anotadas, err):
    """Devuelve el _seguro real de la clase del servidor, con dobles."""
    fn = None
    for n in ast.walk(ARBOL):
        if isinstance(n, ast.ClassDef) and n.name == "H":
            for m in n.body:
                if isinstance(m, ast.FunctionDef) and m.name == "_seguro":
                    fn = m
    assert fn, "no se encontro H._seguro"
    ns = {"sys": type("S", (), {"stderr": err})(),
          "traceback": __import__("traceback"), "html": __import__("html"),
          "bitacora": lambda a, d="": anotadas.append((a, d))}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<h>", "exec"), ns)
    return ns["_seguro"]


class Peticion:
    """Un 'self' de mentira con lo justo que usa _seguro."""
    def __init__(self, respondido=False):
        self.path = "/documentacion?embed=1"
        self.command = "GET"
        self.close_connection = False
        self._respondido = respondido
        self.respuestas = []

    def _html(self, s, code=200):
        self.respuestas.append((code, s))


def main():
    # --- 1) la pagina revienta antes de responder ---
    anotadas = []; err = io.StringIO()
    seguro = cargar_seguro(anotadas, err)
    p = Peticion()
    def revienta():
        raise ValueError("algo se rompio generando la guia")
    seguro(p, revienta)

    check("no se propaga: la conexion no se queda muerta", True)
    check("se responde una pagina de error", len(p.respuestas) == 1, p.respuestas)
    code, cuerpo = p.respuestas[0] if p.respuestas else (0, "")
    check("con codigo 500", code == 500, code)
    check("que dice QUE peticion fallo", "/documentacion" in cuerpo, cuerpo[:200])
    check("y que el resto del panel sigue vivo", "sigue funcionando" in cuerpo, cuerpo[:200])
    check("y donde mirar el detalle", "journalctl -u suricata-dashboard" in cuerpo, cuerpo[:200])
    check("el traceback completo va al log del servicio",
          "ValueError" in err.getvalue() and "Traceback" in err.getvalue(), err.getvalue()[:200])
    check("y queda en la bitacora, con la ruta",
          anotadas and anotadas[0][0] == "ERROR-PANEL" and "/documentacion" in anotadas[0][1],
          anotadas)

    # --- 2) si ya habia empezado a responder, no se escribe una segunda respuesta ---
    anotadas2 = []; err2 = io.StringIO()
    seguro2 = cargar_seguro(anotadas2, err2)
    p2 = Peticion(respondido=True)
    seguro2(p2, revienta)
    check("una respuesta a medias no se pisa con otra", p2.respuestas == [], p2.respuestas)
    check("se corta la conexion en su lugar", p2.close_connection is True)
    check("pero el fallo igual queda anotado", len(anotadas2) == 1, anotadas2)

    # --- 3) si el que se fue es el cliente, no hay nada que responder ---
    p3 = Peticion()
    def se_fue():
        raise BrokenPipeError(32, "Broken pipe")
    try:
        seguro(p3, se_fue)
        subio = False
    except BrokenPipeError:
        subio = True
    check("un cliente que cuelga no genera pagina de error", subio and p3.respuestas == [],
          p3.respuestas)

    # --- 4) lo normal sigue siendo normal ---
    p4 = Peticion()
    seguro(p4, lambda: p4.respuestas.append((200, "ok")))
    check("una peticion correcta no se toca", p4.respuestas == [(200, "ok")], p4.respuestas)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
