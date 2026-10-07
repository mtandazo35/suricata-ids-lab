# -*- coding: utf-8 -*-
"""Los dominios de los feeds pasan a ser DETECCION: un dataset de Suricata.

Hoy URLhaus/ThreatFox se bajan y el panel cruza los dominios DESPUES, leyendo dns.json.
Con `dataset` la consulta a un dominio fichado es una ALERTA en el momento. Es lo que
habria cazado lo que la atribucion no encontro.

Dos trampas, las dos reales en Suricata 7.0.10, que es lo que corre en los sensores:
  - un dataset de tipo `string` guarda cada valor en BASE64. En claro no casa NUNCA, y no
    da error: parece que funciona y no detecta nada.
  - una regla con `load` de un archivo que no existe tumba la carga de TODAS las reglas al
    arrancar. El instalador deja el archivo creado, vacio, antes de que Suricata arranque.
"""
import base64
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_f = SRC.index("cat > /usr/local/bin/suricata-feeds-update <<'FEEDS'")
FEEDS = SRC[_f:].split("\n", 1)[1].split("\nFEEDS\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def bloque_dataset():
    """El trozo del feeds-update que escribe el dataset, tal cual esta en el instalador.
    Se ejecuta con un DIR temporal y un subprocess de mentira que anota lo que haria."""
    ini = FEEDS.index("import base64, subprocess")
    fin = FEEDS.index("    except (OSError, subprocess.TimeoutExpired) as e:")
    fin = FEEDS.index("\n", FEEDS.index("dataset: no se pudo validar", fin)) + 1
    return FEEDS[ini:fin]


class _Run(object):
    def __init__(self, rc_T=0):
        self.llamadas = []
        self.rc_T = rc_T

    def __call__(self, cmd, **k):
        self.llamadas.append(list(cmd))
        rc = self.rc_T if cmd[:2] == ["suricata", "-T"] else 0
        return type("R", (), {"returncode": rc, "stderr": "", "stdout": ""})()


def correr(dom_lines, dir_, rc_T=0, previo=None):
    run = _Run(rc_T)
    sub = type("S", (), {"run": staticmethod(run), "TimeoutExpired": Exception})
    ns = {"os": os, "DIR": dir_, "dom_lines": list(dom_lines),
          "__builtins__": __builtins__}
    if previo is not None:
        open(os.path.join(dir_, "domains.dataset"), "w", encoding="utf-8").write(previo)
    codigo = bloque_dataset().replace("import base64, subprocess", "import base64")
    ns["subprocess"] = sub
    exec(codigo, ns)
    ruta = os.path.join(dir_, "domains.dataset")
    try:
        return open(ruta, encoding="utf-8").read(), run.llamadas
    except OSError:
        return None, run.llamadas


def main():
    # =====================================================================================
    # Base64 por linea, o no casa nunca
    # =====================================================================================
    d = tempfile.mkdtemp()
    txt, llam = correr(["dontworry.su\turlhaus", "Malo.Example.NET.\tthreatfox"], d)
    lineas = txt.strip().split("\n")
    check("cada dominio va en base64, una linea por dominio",
          base64.b64encode(b"dontworry.su").decode() in lineas, lineas)
    check("en minusculas y sin el punto final: el dataset compara exacto",
          base64.b64encode(b"malo.example.net").decode() in lineas, lineas)
    check("y NO en claro, que es lo que parece funcionar y no detecta nada",
          "dontworry.su" not in txt, txt)
    check("sin repetidos", len(lineas) == len(set(lineas)) == 2, lineas)

    # un dato raro de un feed no puede romper la carga de reglas
    d2 = tempfile.mkdtemp()
    txt, _ = correr(["bueno.net\tx", ("a" * 70) + ".com\tx", "con espacio.com\tx", "\tx"], d2)
    check("una etiqueta de mas de 63 caracteres se descarta",
          base64.b64encode(b"bueno.net").decode() in txt and txt.strip().count("\n") == 0, txt)
    check("un dominio con espacio tambien", base64.b64encode(b"con espacio.com").decode() not in txt, "")

    # =====================================================================================
    # Validar antes de recargar, y no recargar si nada cambio
    # =====================================================================================
    d3 = tempfile.mkdtemp()
    _, llam = correr(["x.net\tf"], d3)
    check("se valida con suricata -T antes de recargar",
          llam and llam[0][:2] == ["suricata", "-T"], llam)
    check("y luego se recarga en caliente",
          any(c[:1] == ["suricatasc"] for c in llam), llam)
    orden_ok = [c[0] for c in llam]
    check("en ese orden: -T primero", orden_ok.index("suricata") < orden_ok.index("suricatasc"), orden_ok)

    # mismo contenido -> no se reescribe ni se recarga: el cron corre cada 15 min
    ya = base64.b64encode(b"x.net").decode() + "\n"
    _, llam2 = correr(["x.net\tf"], tempfile.mkdtemp(), previo=ya)
    check("si el dataset no cambio, no se toca a Suricata", llam2 == [], llam2)

    # si -T falla, NO se recarga: un dataset que no carga deja el sensor sin reglas
    _, llam3 = correr(["y.net\tf"], tempfile.mkdtemp(), rc_T=1)
    check("si suricata -T falla, no se recarga",
          not any(c[:1] == ["suricatasc"] for c in llam3), llam3)

    # =====================================================================================
    # La regla y el instalador
    # =====================================================================================
    reg = [l for l in SRC.split("\n") if "dataset:isset,feeds-dominios" in l and l.startswith("alert dns")]
    check("hay una regla DNS que consulta el dataset", len(reg) == 1, reg)
    if reg:
        r = reg[0]
        check("de tipo string, que es el que va en base64", "type string" in r, r)
        check("cargando el archivo que escribe feeds-update",
              "load /var/lib/suricata-feeds/domains.dataset" in r, r)
        check("con sid en el rango local (9000000+)", "sid:90000" in r, r)
        check("y mirando dns.query, no el paquete entero", "dns.query;" in r, r)
    # una regla con load de un archivo inexistente tumba TODAS las reglas al arrancar
    check("el instalador crea el dataset (vacio) ANTES de que arranque Suricata",
          "[ -f /var/lib/suricata-feeds/domains.dataset ] || : >" in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
