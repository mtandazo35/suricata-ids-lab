# -*- coding: utf-8 -*-
"""Las claves que entrega el instalador: que siempre se puedan usar.

De donde sale (caja nueva, 2026-10-10):
  - la 1a ejecucion creo la clave del panel, la imprimio a mitad y murio antes del resumen;
  - la 2a ya no podia leerla (el panel la guarda hasheada) y el resumen decia
    "<ya configurada>": el operador no tenia con que entrar;
  - y EveBox tenia OTRA clave distinta: probaba la de una web en la otra y "no entraba".

Lo que se protege (ejecutando el trozo REAL del instalador, con /etc redirigido):
  - instalacion nueva: una sola clave para panel y EveBox, y queda la marca de "pendiente
    de entregar";
  - si una ejecucion anterior la creo y no la entrego (marca presente, clave ya hasheada):
    se pone una nueva y se entrega, y con ESA se entra (verificado con el _hash_pw del panel);
  - reinstalacion normal (sin marca, sin -P): no se toca la clave de nadie;
  - con -P: la clave del panel pasa a ser la de -P;
  - el resumen borra la marca al final y, si no tiene la clave, dice como recuperarla.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


# el _hash_pw del PANEL: si la clave que pone el instalador no verifica con el, no se entra
ns = {"secrets": __import__("secrets"), "hashlib": __import__("hashlib")}
for n in ast.parse(DASH).body:
    if isinstance(n, ast.FunctionDef) and n.name == "_hash_pw":
        exec(ast.get_source_segment(DASH, n), ns)
hash_pw = ns["_hash_pw"]


def trozo(etc):
    """Bloque de claves + creacion del .conf + lectura/reset, tal cual, con /etc -> etc."""
    ini = SRC.index("# --- claves de acceso ---")
    fin_conf = SRC.index("\nfi\n", SRC.index("if [ ! -f /etc/suricata-dashboard.conf ]; then", ini)) + 4
    i2 = SRC.index('DASH_PASS_SHOWN="$(awk')
    f2 = SRC.index("\nfi\n", SRC.index('_np="${WEB_PASS:-$GEN_PASS}"', i2)) + 4
    t = SRC[ini:fin_conf] + SRC[i2:f2]
    t = t.replace("/etc/suricata-dashboard", etc + "/suricata-dashboard")
    cab = ("set -euo pipefail\nok(){ :; }\nwarn(){ echo \"WARN $*\"; }\n"
           "HOME_NET_GIVEN=0; HOME_NET=''\n")
    pie = '\necho "SHOWN=$DASH_PASS_SHOWN"\necho "GEN=$GEN_PASS"\n'
    return cab + t + pie


def correr(etc, web_pass=""):
    r = subprocess.run(["bash", "-c", trozo(etc)], capture_output=True, text=True,
                       env=dict(os.environ, WEB_PASS=web_pass))
    out = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l and l.split("=", 1)[0] in ("SHOWN", "GEN"))
    return r, out


def entra(etc, pw):
    lst = json.load(open(os.path.join(etc, "suricata-dashboard-users.json"), encoding="utf-8"))
    a = next(x for x in lst if x["user"] == "admin")
    return hash_pw(pw, a["salt"])[1] == a["hash"]


def migrar(etc, pw):
    """Lo que hace el panel al arrancar: la clave del .conf pasa hasheada a users.json."""
    salt, h = hash_pw(pw)
    json.dump([{"user": "admin", "salt": salt, "hash": h, "role": "admin"}],
              open(os.path.join(etc, "suricata-dashboard-users.json"), "w", encoding="utf-8"))
    conf = os.path.join(etc, "suricata-dashboard.conf")
    txt = open(conf, encoding="utf-8").read()
    open(conf, "w", encoding="utf-8").write(re.sub(r"(?m)^PASS=.*$", "PASS=", txt))


def main():
    etc = tempfile.mkdtemp().replace("\\", "/")
    pend = os.path.join(etc, "suricata-dashboard.pendiente")

    # 1) instalacion nueva
    r, o = correr(etc)
    check("instalacion nueva: el trozo real corre sin errores", r.returncode == 0, r.stderr[-300:])
    check("  entrega la clave del panel, y es la comun (la misma que usara EveBox)",
          o.get("SHOWN") and o.get("SHOWN") == o.get("GEN") and len(o["SHOWN"]) == 16, o)
    check("  y deja la marca de 'pendiente de entregar'", os.path.exists(pend), "")
    primera = o.get("SHOWN", "")

    # 2) la ejecucion murio antes del resumen; el panel ya la hasheo; se reinstala
    migrar(etc, primera)
    r, o = correr(etc)
    nueva = o.get("SHOWN", "")
    check("si la anterior no la entrego (marca + clave hasheada): pone una nueva y la entrega",
          r.returncode == 0 and nueva and nueva != primera, (o, r.stderr[-300:]))
    check("  y con ESA se entra al panel (hash del propio panel)", entra(etc, nueva), "")
    check("  la vieja ya no vale", not entra(etc, nueva + "x") and not entra(etc, primera), "")

    # 3) el resumen se imprimio (se borra la marca): reinstalar no toca nada
    os.remove(pend)
    r, o = correr(etc)
    check("reinstalacion normal (sin marca ni -P): no cambia la clave del panel",
          o.get("SHOWN") == "" and entra(etc, nueva), o)

    # 4) con -P: la del panel pasa a ser esa
    r, o = correr(etc, web_pass="ClaveNueva123")
    check("con -P: el panel queda con esa clave y se entrega",
          o.get("SHOWN") == "ClaveNueva123" and entra(etc, "ClaveNueva123"), o)

    # 5) -P en una instalacion nueva: la conf nace con esa
    etc2 = tempfile.mkdtemp().replace("\\", "/")
    r, o = correr(etc2, web_pass="OtraClave456")
    check("con -P en una caja nueva: el panel nace con esa clave", o.get("SHOWN") == "OtraClave456", o)

    # ---- el resumen ----
    check("el resumen borra la marca al final (la clave ya se entrego)",
          SRC.rstrip("\n").endswith('rm -f "$DASH_PEND"'), SRC.rstrip("\n")[-80:])
    check("EveBox se crea con la MISMA clave que el panel",
          '_evb_pass="${WEB_PASS:-$GEN_PASS}"' in SRC and '--password "$_evb_pass"' in SRC, "")
    check("sin la clave, el resumen dice como recuperarla (-P), no solo '<ya configurada>'",
          "Clave      : ${DASH_PASS_SHOWN:-<ya configurada" not in SRC
          and "re-ejecuta el instalador con -P 'NuevaClave'" in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
