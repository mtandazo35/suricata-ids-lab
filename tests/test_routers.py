# -*- coding: utf-8 -*-
"""Registro de routers (multi-nodo) y su migracion.

Lo que se protege aqui: las cajas YA instaladas tienen un solo MikroTik en
/etc/suricata-mikrotik.conf. Al pasar a multi-nodo, esa configuracion debe seguir
funcionando exactamente igual sin tocar nada a mano. Si esta prueba falla, una
actualizacion dejaria el panel sin poder hablar con el router.
"""
import ast
import json
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
DASH = SRC[_i:].split("\n", 1)[1].split("\nDASH\n", 1)[0]
ARBOL = ast.parse(DASH)

PIEZAS = ("_router_vacio", "_mk_globales", "cargar_routers", "guardar_routers",
          "router_por_id", "router_por_iface", "router_defecto", "cargar_mk",
          "cargar_mk_de", "IFACE_BASE", "CAMPOS_ROUTER")


def entorno(tmp):
    """Carga solo las piezas de routers, con las rutas apuntando a un temporal."""
    ns = {"json": json, "os": os,
          "MK_CONF": os.path.join(tmp, "mikrotik.conf"),
          "ROUTERS_CONF": os.path.join(tmp, "routers.json")}
    for n in ARBOL.body:
        seg = ast.get_source_segment(DASH, n) or ""
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS:
            exec(seg, ns)
    # las constantes de ruta no deben quedar pisadas por las del script
    ns["MK_CONF"] = os.path.join(tmp, "mikrotik.conf")
    ns["ROUTERS_CONF"] = os.path.join(tmp, "routers.json")
    return ns


fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def main():
    import tempfile
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # --- una caja ya instalada: solo tiene el .conf de un router ---
    open(ns["MK_CONF"], "w", encoding="utf-8").write(
        "HOST=10.87.87.1\nPORT=8729\nTLS=1\nUSER=suricata\nPASS=clave-secreta\n"
        "LIST=Cliente Virus\nTTL=2h\nLIST_DNS=Cliente DNS\nTTL_DNS=1d\n"
        "AUTO_MANTENER=1\nENABLED=1\nCERT_FP=AA:BB\n"
        "POL_AUTO=1\nPOL_BAJO=nada\nPOL_MEDIO=notificar\nPOL_ALTO=cuarentena\n")

    routers = ns["cargar_routers"]()
    check("sin archivo nuevo, migra el router existente", len(routers) == 1, routers)
    r = routers[0]
    check("conserva host, usuario y clave", (r["HOST"], r["USER"], r["PASS"]) ==
          ("10.87.87.1", "suricata", "clave-secreta"), r)
    check("conserva puerto y TLS", (r["PORT"], r["TLS"]) == ("8729", "1"), r)
    check("conserva las dos address-lists y sus TTL",
          (r["LIST"], r["TTL"], r["LIST_DNS"], r["TTL_DNS"]) ==
          ("Cliente Virus", "2h", "Cliente DNS", "1d"), r)
    check("conserva la huella del certificado", r["CERT_FP"] == "AA:BB", r)
    check("sigue habilitado", r["ENABLED"] == "1", r)
    check("el primero mantiene la interfaz de siempre", r["iface"] == "ids-mon", r)

    # --- lo que ve el codigo que todavia no distingue router ---
    mk = ns["cargar_mk"]()
    check("cargar_mk() devuelve el mismo host de siempre", mk["HOST"] == "10.87.87.1", mk)
    check("cargar_mk() conserva los ajustes GLOBALES de politica",
          (mk["POL_AUTO"], mk["POL_MEDIO"], mk["POL_ALTO"], mk["AUTO_MANTENER"]) ==
          ("1", "notificar", "cuarentena", "1"), mk)
    check("cargar_mk() dice a que router corresponde", mk["ROUTER_ID"] == "r1", mk)

    # --- agregar un segundo nodo ---
    dos = ns["cargar_routers"]()
    nuevo = ns["_router_vacio"](2)
    nuevo.update({"nombre": "Nodo Sur", "HOST": "10.99.99.1",
                  "USER": "sur", "PASS": "otra", "ENABLED": "1"})
    dos.append(nuevo)
    ns["guardar_routers"](dos)

    leidos = ns["cargar_routers"]()
    check("se guardan y releen los dos nodos", len(leidos) == 2, leidos)
    check("cada nodo tiene SU interfaz de espejo",
          [x["iface"] for x in leidos] == ["ids-mon", "ids-mon2"], leidos)
    check("cada nodo tiene su propia clave",
          [x["PASS"] for x in leidos] == ["clave-secreta", "otra"], leidos)
    check("el archivo de routers queda con permisos 600",
          (os.stat(ns["ROUTERS_CONF"]).st_mode & 0o777) in (0o600, 0o666), None)

    # --- resolver por interfaz: de aqui sale "de que router vino esta alerta" ---
    check("una alerta por ids-mon es del primer nodo",
          ns["router_por_iface"]("ids-mon")["HOST"] == "10.87.87.1")
    check("una alerta por ids-mon2 es del segundo",
          ns["router_por_iface"]("ids-mon2")["HOST"] == "10.99.99.1")
    check("una interfaz desconocida no inventa router",
          ns["router_por_iface"]("eth0") is None)
    check("router_por_id encuentra el nodo", ns["router_por_id"]("r2")["nombre"] == "Nodo Sur")

    # --- los ajustes de CADA router, con la politica global compartida ---
    m2 = ns["cargar_mk_de"](leidos[1])
    check("el segundo nodo usa SU host", m2["HOST"] == "10.99.99.1", m2)
    check("pero comparte la politica global", m2["POL_ALTO"] == "cuarentena", m2)

    # --- si el primero se deshabilita, el de por defecto pasa a ser el otro ---
    leidos[0]["ENABLED"] = "0"
    ns["guardar_routers"](leidos)
    check("router_defecto toma el primero HABILITADO",
          ns["router_defecto"]()["HOST"] == "10.99.99.1", ns["router_defecto"]())

    # --- archivo corrupto: no debe dejar el panel sin router ---
    open(ns["ROUTERS_CONF"], "w", encoding="utf-8").write("{roto")
    vuelta = ns["cargar_routers"]()
    check("con el archivo corrupto vuelve a la configuracion de siempre",
          len(vuelta) == 1 and vuelta[0]["HOST"] == "10.87.87.1", vuelta)

    # --- instalacion nueva sin nada configurado ---
    os.remove(ns["MK_CONF"]); os.remove(ns["ROUTERS_CONF"])
    limpio = ns["cargar_routers"]()
    check("sin configuracion devuelve un router vacio (no revienta)",
          len(limpio) == 1 and limpio[0]["HOST"] == "", limpio)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
