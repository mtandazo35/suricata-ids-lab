# -*- coding: utf-8 -*-
"""Salir de las listas negras: cuando se puede pedir, con que pruebas y donde.

Lo que protege:
  - Que NO se invite a pedir la salida con el abuso vivo. Pedirla mientras el CPE sigue
    emitiendo te vuelve a listar, y varias listas penalizan la reincidencia: es el error
    que mas caro sale y el que un automatismo comete solo.
  - Que un dia SIN DATO no cuente como dia limpio. Si el panel estuvo caido dos dias eso
    no es limpieza, y contarlo como tal adelantaria la peticion.
  - Que no se mande a rellenar formularios de listas que caducan solas: es trabajo que no
    sirve de nada y ensucia tu reputacion ante quien las gestiona.
  - Que la PBL no dispare nada. En un rango residencial estar en la PBL es lo normal y lo
    correcto; tratarla como problema seria pedir salidas que no proceden.
"""
import ast
import os
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("DNSBL", "DNSBL_SALIDA", "DNSBL_DIAS_LIMPIO", "dias_sin_abuso",
          "dnsbl_tendencia", "dnsbl_listas_afectadas", "dnsbl_salida",
          "dnsbl_expediente", "_SAL_COLOR", "_SAL_POL", "_salida_html")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno():
    ns = {"os": os, "time": time, "html": __import__("html")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def dia(n):
    return time.strftime("%Y-%m-%d", time.localtime(time.time() - n * 86400))


def main():
    ns = entorno()

    # --- dias sin abuso ------------------------------------------------------------------
    met = {dia(i): {"sal": 0} for i in range(1, 8)}
    check("con una semana a cero, son 7 dias limpios", ns["dias_sin_abuso"](met) == 7,
          ns["dias_sin_abuso"](met))

    met2 = dict(met); met2[dia(3)] = {"sal": 12}
    check("un dia con abuso corta la cuenta", ns["dias_sin_abuso"](met2) == 2,
          ns["dias_sin_abuso"](met2))

    met3 = dict(met); del met3[dia(3)]
    check("y un dia SIN DATO tambien la corta: no es lo mismo que un dia tranquilo",
          ns["dias_sin_abuso"](met3) == 2, ns["dias_sin_abuso"](met3))

    check("sin historial, cero dias limpios", ns["dias_sin_abuso"]({}) == 0)

    # --- el estado --------------------------------------------------------------------------
    bl_barracuda = {"ts": 1, "n_listadas": 2,
                    "ips": {"203.0.113.10": {"listas": ["Barracuda", "Spamhaus ZEN"]},
                            "203.0.113.11": {"listas": ["Barracuda"]}},
                    "dias": {dia(6): 9, dia(3): 5, dia(0): 2}}

    e = ns["dnsbl_salida"](bl_barracuda, 0)
    check("con abuso reciente NO se invita a pedir la salida", e["estado"] == "espera", e)
    check("y se dice por que: primero se corta, luego se pide",
          "vuelve a listar" in e["detalle"], e["detalle"])

    e = ns["dnsbl_salida"](bl_barracuda, 5)
    check("con 5 dias limpios ya se puede pedir", e["estado"] == "pedir", e)

    # --- listas que se salen solas -----------------------------------------------------------
    bl_solas = {"ts": 1, "n_listadas": 1,
                "ips": {"203.0.113.10": {"listas": ["Spamhaus ZEN", "SpamCop"]}},
                "dias": {dia(0): 1}}
    e = ns["dnsbl_salida"](bl_solas, 5)
    check("si todas caducan solas, no se manda a rellenar nada",
          e["estado"] == "caduca", e)
    check("y se dice que pedirlo no lo adelanta", "no lo adelanta" in e["detalle"],
          e["detalle"])

    # --- la PBL no es un problema -------------------------------------------------------------
    bl_pbl = {"ts": 1, "n_listadas": 0, "n_pbl": 40,
              "ips": {"203.0.113.10": {"listas": ["Spamhaus ZEN"], "solo_pbl": True}},
              "dias": {dia(0): 0}}
    check("estar solo en la PBL no genera ninguna gestion",
          ns["dnsbl_salida"](bl_pbl, 9)["estado"] == "limpio",
          ns["dnsbl_salida"](bl_pbl, 9))
    check("y no se pinta bloque", ns["_salida_html"]("203.0.113.0/24", bl_pbl, 9) == "")
    check("una entrada sin revisar tampoco pinta nada",
          ns["_salida_html"]("203.0.113.0/24", {}, 9) == "")

    # --- la tendencia, que es la prueba de que cortar sirvio ------------------------------------
    t = ns["dnsbl_tendencia"](bl_barracuda)
    check("el pico se recuerda", t["pico"] == 9, t)
    check("y se compara con hoy", t["hoy"] == 2, t)
    check("va bajando", t["dir"] == "baja", t)
    check("sin historial no se inventa tendencia", ns["dnsbl_tendencia"]({})["pico"] == 0)

    # --- el expediente ----------------------------------------------------------------------
    e = ns["dnsbl_salida"](bl_barracuda, 5)
    txt = ns["dnsbl_expediente"]("203.0.113.0/24", bl_barracuda, e,
                                 ns["dnsbl_tendencia"](bl_barracuda))
    check("el expediente nombra la entrada", "203.0.113.0/24" in txt, txt[:90])
    check("lista las direcciones afectadas", "203.0.113.10" in txt, "")
    check("dice cuantos dias lleva sin abuso", "5 consecutive days" in txt, "")
    check("y aporta la bajada, que es lo que casi nadie puede demostrar",
          "from 9 at peak to 2 today" in txt, "")

    # --- lo que se ve --------------------------------------------------------------------------
    h = ns["_salida_html"]("203.0.113.0/24", bl_barracuda, 5)
    check("con derecho a pedir, sale el texto del formulario",
          "Texto para el formulario" in h, h[:200])
    check("y el enlace de la lista que lo exige",
          "barracudacentral.org" in h, "")
    check("los enlaces externos no ceden la pestana",
          h.count("rel='noopener noreferrer'") >= 1, "")
    h2 = ns["_salida_html"]("203.0.113.0/24", bl_barracuda, 0)
    check("sin derecho a pedir, NO se ofrece el texto",
          "Texto para el formulario" not in h2, h2[:200])

    # --- SORBS -------------------------------------------------------------------------------
    # Cerro en 2024 y el chequeo se quedo consultando al vacio. Mientras siga en DNSBL,
    # al menos que la pantalla diga que ese dato no significa nada.
    check("SORBS esta marcada como servicio cerrado",
          ns["DNSBL_SALIDA"]["dnsbl.sorbs.net"][0] == "muerta",
          ns["DNSBL_SALIDA"].get("dnsbl.sorbs.net"))
    check("toda lista consultada tiene politica de salida declarada",
          all(z in ns["DNSBL_SALIDA"] for z, _n in ns["DNSBL"]),
          [z for z, _n in ns["DNSBL"] if z not in ns["DNSBL_SALIDA"]])
    check("y toda politica es una de las cuatro conocidas",
          all(v[0] in ("sola", "formulario", "pago", "muerta")
              for v in ns["DNSBL_SALIDA"].values()),
          [v[0] for v in ns["DNSBL_SALIDA"].values()])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    raise SystemExit(main())
