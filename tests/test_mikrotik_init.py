# -*- coding: utf-8 -*-
"""suricata-mikrotik-init contra un MikroTik de mentira.

Lo que protege, por orden de lo que costaria el fallo:

  - Que repetirlo NO duplique reglas. Un espejo duplicado es lo que en produccion metio
    886 Mbps en un enlace para que el receptor tirase el 91%, y con el enlace lleno el
    TZSP (UDP) no se retrasa: desaparece. Un instalador que se puede correr dos veces
    tiene que ser idempotente o se convierte en la causa del problema que resuelve.
  - Que NO toque espejos que apuntan a otro sensor. El router es del cliente y puede
    tener lo suyo; solo se apaga lo que viene hacia nosotros.
  - Que el DNS nunca lleve connection-bytes: es diminuto y es donde mas se detecta.
  - Que en modo local NO se ponga recorte, y en vpn si.
  - Que NO active el envio solo: cortarle el internet a un abonado lo decide una persona.
  - Que la clave salga de un archivo y nunca de la linea de comandos.
  - Que la vista previa (--plan, la usa el panel antes de confirmar) NO toque nada y diga
    lo mismo que despues se aplica; que --sin-registrar no pise la configuracion del panel.
  - Que con api-ssl y sin huella previa conecte (antes moria con un NameError).
  - Que se pare en el PRIMER fallo (y sin respaldo /export no toque nada): seguir podia dejar
    el espejo nuevo creado y el viejo sin apagar, dos espejos llenando el enlace.
  - Que la clave llegue tal cual (espacios o comillas en los bordes son parte de ella).
"""
import contextlib
import ast
import io
import json
import os
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

_i = SRC.index("cat > /usr/local/bin/suricata-mikrotik-init <<'MKINIT'")
PROG = SRC[_i:].split("\n", 1)[1].split("\nMKINIT\n", 1)[0]

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class Router(object):
    """Un MikroTik de mentira: recuerda lo que le mandan y contesta lo que le pongas."""

    def __init__(self, mangle=(), filtro=(), lista=()):
        self.mangle = [dict(x) for x in mangle]
        self.filtro = [dict(x) for x in filtro]
        self.lista = [dict(x) for x in lista]
        self.ordenes = []          # [(comando, {clave: valor})]
        self.falla = None          # una orden que el router rechaza

    def ns(self):
        r = self

        def _print(_s, cmd, _props):
            if cmd.startswith("/ip/firewall/mangle"):
                return [dict(x) for x in r.mangle]
            if cmd.startswith("/ip/firewall/filter"):
                return [dict(x) for x in r.filtro]
            if cmd.startswith("/ip/firewall/address-list"):
                return [dict(x) for x in r.lista]
            return []

        def _send(_s, palabras):
            cmd = palabras[0]
            args = {}
            for a in palabras[1:]:
                if a.startswith("=") and "=" in a[1:]:
                    k, v = a[1:].split("=", 1)
                    args[k] = v
            r.ordenes.append((cmd, args))
            if cmd == "/ip/firewall/mangle/add":
                nueva = dict(args)
                nueva[".id"] = "*%d" % (len(r.mangle) + 90)
                nueva["action"] = args.get("action", "")
                r.mangle.append(nueva)

        def _reply(_s):
            if r.falla and r.ordenes and r.ordenes[-1][0] == r.falla:
                return False, [], "failure: sin permiso"
            return True, [], ""

        class Sock(object):
            def getpeercert(self, binary_form=False):
                return None        # api-ssl sin certificado: DH anonimo

            def close(self):
                pass

        return {"mk_conectar": lambda d, timeout=6: Sock(),
                "_mk_print": _print, "_mk_send": _send, "_mk_reply": _reply}


def correr(router, tmp, *args):
    """Ejecuta la herramienta con ese router de mentira. Devuelve el modulo ya usado."""
    ns = {"__name__": "prueba"}
    exec(compile(PROG, "<mkinit>", "exec"), ns)
    ns["MK_CONF"] = os.path.join(tmp, "mikrotik.conf")
    ns["ROUTERS_CONF"] = os.path.join(tmp, "routers.json")
    ns["cliente_api"] = router.ns
    cred = os.path.join(tmp, "cred.conf")
    io.open(cred, "w", encoding="utf-8", newline="\n").write(
        "HOST=192.0.2.1\nPORT=8729\nUSER=ids\nPASS=secreta\n")
    os.chmod(cred, 0o600)
    viejo = sys.argv
    sys.argv = ["mkinit", "-k", cred, "-s", "198.51.100.9"] + list(args)
    try:
        ns["main"]()
    finally:
        sys.argv = viejo
    return ns


def correr_salida(router, tmp, *args):
    """Como correr(), pero devuelve tambien lo que imprime y lo que retorna main()."""
    ns = {"__name__": "prueba"}
    exec(compile(PROG, "<mkinit>", "exec"), ns)
    ns["MK_CONF"] = os.path.join(tmp, "mikrotik.conf")
    ns["ROUTERS_CONF"] = os.path.join(tmp, "routers.json")
    ns["cliente_api"] = router.ns
    cred = os.path.join(tmp, "cred.conf")
    io.open(cred, "w", encoding="utf-8", newline="\n").write(
        "HOST=100.64.0.2\nPORT=8728\nTLS=0\nUSER=ids\nPASS=secreta\n")
    viejo = sys.argv
    sys.argv = ["mkinit", "-k", cred, "-s", "100.64.0.1"] + list(args)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = ns["main"]()
    finally:
        sys.argv = viejo
    return rc, buf.getvalue()


def reglas_creadas(r):
    return [a for c, a in r.ordenes if c == "/ip/firewall/mangle/add"]


def reglas_tocadas(r):
    return [a for c, a in r.ordenes if c == "/ip/firewall/mangle/set"]


def main():
    tmp = tempfile.mkdtemp()

    # --- primera pasada, router limpio, modo vpn ---------------------------------------
    r = Router(lista=[{"list": "ids-vigilados", "address": "192.168.0.0/19"}])
    correr(r, tmp, "-e", "vpn", "-r", "192.168.0.0/19")
    creadas = reglas_creadas(r)
    check("crea las tres reglas: ida, vuelta y DNS", len(creadas) == 3, len(creadas))
    ida = [x for x in creadas if x.get("comment", "").endswith("(ida)")][0]
    vue = [x for x in creadas if x.get("comment", "").endswith("(vuelta)")][0]
    dns = [x for x in creadas if "DNS" in x.get("comment", "")][0]
    check("las dos de trafico van en forward",
          ida["chain"] == "forward" and vue["chain"] == "forward", (ida, vue))
    check("la vuelta mira el destino, no el origen",
          "dst-address-list" in vue and "src-address-list" not in vue, vue)
    check("en modo vpn llevan recorte",
          ida.get("connection-bytes") == "0-10000", ida)
    check("el DNS NUNCA lleva recorte: es diminuto y detecta mucho",
          "connection-bytes" not in dns, dns)
    check("y apuntan a este sensor", ida["sniff-target"] == "198.51.100.9", ida)

    # --- el respaldo antes de tocar el firewall ------------------------------------------
    check("se exporta la configuracion antes de tocar nada",
          any(c == "/export" for c, _a in r.ordenes), [c for c, _ in r.ordenes][:4])

    # --- lo que NO hace ------------------------------------------------------------------
    conf = io.open(os.path.join(tmp, "mikrotik.conf"), encoding="utf-8").read()
    check("el router queda dado de alta en el panel", "HOST=192.0.2.1" in conf, conf[:80])
    check("pero el envio NO se activa solo: cortar lo decide una persona",
          "ENABLED=0" in conf, [l for l in conf.splitlines() if "ENABLED" in l])
    # En Windows os.chmod solo mueve el bit de solo-lectura, asi que el modo real no se
    # puede comprobar ahi. Se mide de verdad donde importa (el servidor es Linux) y en
    # Windows se comprueba la intencion, diciendo cual de las dos se esta haciendo.
    if os.name == "posix":
        modo = os.stat(os.path.join(tmp, "mikrotik.conf")).st_mode
        check("la configuracion no la puede leer otro usuario (modo real)",
              (modo & 0o077) == 0, oct(modo))
    else:
        check("la configuracion se guarda con permisos 600 (no medible en Windows)",
              "os.chmod(tmp, 0o600)" in PROG, "")

    # --- segunda pasada: NO puede duplicar -------------------------------------------------
    # Este es el fallo caro. Un instalador idempotente se corre dos veces sin pensarlo.
    r2 = Router(mangle=[dict(x, **{".id": "*%d" % (i + 1), "action": "sniff-tzsp"})
                        for i, x in enumerate(creadas)],
                lista=[{"list": "ids-vigilados", "address": "192.168.0.0/19"}])
    correr(r2, tmp, "-e", "vpn", "-r", "192.168.0.0/19")
    check("repetirlo no crea ninguna regla nueva", reglas_creadas(r2) == [],
          reglas_creadas(r2))
    check("las actualiza en su sitio", len(reglas_tocadas(r2)) >= 3, reglas_tocadas(r2))
    check("y no vuelve a meter la red en la lista",
          not any(c.endswith("address-list/add") for c, _a in r2.ordenes), r2.ordenes)

    # --- espejos ajenos: no se tocan --------------------------------------------------------
    ajeno = {".id": "*50", "action": "sniff-tzsp", "comment": "espejo de otro IDS",
             "sniff-target": "203.0.113.77", "disabled": "false", "chain": "forward"}
    propio_viejo = {".id": "*51", "action": "sniff-tzsp", "comment": "IDS",
                    "sniff-target": "198.51.100.9", "disabled": "false", "chain": "forward"}
    r3 = Router(mangle=[ajeno, propio_viejo],
                lista=[{"list": "ids-vigilados", "address": "192.168.0.0/19"}])
    correr(r3, tmp, "-e", "vpn", "-r", "192.168.0.0/19")
    apagadas = [a for a in reglas_tocadas(r3) if a.get("disabled") == "yes"]
    ids = {a[".id"] for a in apagadas}
    check("apaga el espejo viejo que venia hacia NUESTRO sensor", "*51" in ids, ids)
    check("y NO toca el espejo que va a otro sensor: el router es del cliente",
          "*50" not in ids, ids)

    # --- modo local: sin recorte --------------------------------------------------------------
    r4 = Router(lista=[{"list": "ids-vigilados", "address": "10.0.0.0/8"}])
    correr(r4, tmp, "-e", "local", "-r", "10.0.0.0/8")
    c4 = reglas_creadas(r4)
    check("en modo local son dos reglas, sin la de DNS aparte", len(c4) == 2, len(c4))
    check("y ninguna lleva recorte: en la LAN sobra ancho de banda",
          all("connection-bytes" not in x for x in c4), c4)

    # --- fasttrack ----------------------------------------------------------------------------
    r5 = Router(filtro=[{".id": "*9", "action": "fasttrack-connection", "disabled": "false"}],
                lista=[{"list": "ids-vigilados", "address": "10.0.0.0/8"}])
    correr(r5, tmp, "-e", "vpn", "-r", "10.0.0.0/8")
    ft = [a for c, a in r5.ordenes if c == "/ip/firewall/filter/set"]
    check("excluye la lista del fasttrack, sin lo cual mangle solo ve el SYN",
          ft and ft[0].get("src-address-list") == "!ids-vigilados", ft)

    r6 = Router(filtro=[{".id": "*9", "action": "fasttrack-connection",
                         "src-address-list": "!ids-vigilados"}],
                lista=[{"list": "ids-vigilados", "address": "10.0.0.0/8"}])
    correr(r6, tmp, "-e", "vpn", "-r", "10.0.0.0/8")
    check("si ya estaba excluida, no se vuelve a tocar",
          not [a for c, a in r6.ordenes if c == "/ip/firewall/filter/set"], r6.ordenes)

    # --- la clave nunca por la linea de comandos ------------------------------------------------
    check("la herramienta no admite la clave como argumento",
          "--pass" not in PROG and '"-P"' not in PROG, "")
    check("y avisa si el archivo de credenciales lo puede leer otro",
          "legible por otros" in PROG, "")

    # --- vista previa (--plan): la usa el panel antes de confirmar --------------------------
    tmp2 = tempfile.mkdtemp()
    r7 = Router(mangle=[{".id": "*51", "action": "sniff-tzsp", "comment": "IDS", "chain": "forward",
                         "sniff-target": "100.64.0.1", "disabled": "false"}],
                filtro=[{".id": "*9", "action": "fasttrack-connection", "disabled": "false"}])
    rc, out = correr_salida(r7, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--plan")
    tocado = [c for c, _a in r7.ordenes if not c.endswith("/print")]
    check("--plan no toca NADA: ni reglas, ni lista, ni respaldo en el router",
          rc == 0 and tocado == [], tocado)
    check("  ni la configuracion del panel", not os.path.exists(os.path.join(tmp2, "mikrotik.conf"))
          and not os.path.exists(os.path.join(tmp2, "routers.json")), os.listdir(tmp2))
    check("  y dice lo que haria, como se escribe en la terminal del router",
          "VISTA PREVIA" in out
          and "/ip firewall address-list add list=ids-vigilados address=10.20.0.0/16" in out
          and '/ip firewall mangle add action=sniff-tzsp sniff-target=100.64.0.1' in out
          and 'comment="espejo IDS (ida)"' in out and "connection-bytes=0-10000" in out
          and "/ip firewall mangle set *51 disabled=yes" in out
          and "/ip firewall filter set *9 src-address-list=!ids-vigilados" in out, out)
    # lo que se ensena es lo que se aplica: las mismas ordenes, una por linea de la vista
    r8 = Router(mangle=[dict(x) for x in r7.mangle], filtro=[dict(x) for x in r7.filtro])
    rc8, out8 = correr_salida(r8, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    hechas = [c for c, _a in r8.ordenes if not c.endswith("/print") and c != "/export"]
    lineas = [l for l in out.splitlines() if l.startswith("  /")]
    check("lo aplicado son exactamente las ordenes de la vista previa",
          rc8 == 0 and len(hechas) == len(lineas) == 6
          and [h.strip("/").replace("/", " ") for h in hechas] == [" ".join(l.strip().strip("/").split()[:4]) for l in lineas],
          (hechas, lineas))
    check("--sin-registrar aplica en el router pero no pisa la configuracion del panel",
          any(c == "/export" for c, _a in r8.ordenes) and not os.path.exists(os.path.join(tmp2, "mikrotik.conf")), "")
    check("  sin TLS no confunde con el aviso de api-ssl sin certificado",
          "api-ssl SIN certificado" not in out8 and "API sin TLS" in out8, out8[:300])
    r9 = Router()
    r9.falla = "/ip/firewall/mangle/add"
    rc9, out9 = correr_salida(r9, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    check("si el router rechaza una orden, sale con error (el panel lo dice)", rc9 == 1 and "FALLO" in out9, (rc9, out9[-300:]))

    # --- se para en el PRIMER fallo (hallazgo 9) ---------------------------------------------
    # Con un espejo viejo hacia este sensor: si se creaba el nuevo y fallaba apagar el viejo,
    # quedaban DOS espejos llenando el enlace. Ahora el viejo se apaga antes y, si falla, se para.
    viejo = {".id": "*51", "action": "sniff-tzsp", "comment": "IDS", "chain": "forward",
             "sniff-target": "100.64.0.1", "disabled": "false"}
    r10 = Router(mangle=[dict(viejo)], filtro=[{".id": "*9", "action": "fasttrack-connection", "disabled": "false"}])
    r10.falla = "/ip/firewall/mangle/set"          # el router no deja apagar el espejo viejo
    rc10, out10 = correr_salida(r10, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    hechas10 = [c for c, _a in r10.ordenes if not c.endswith("/print")]
    check("si no se puede apagar el espejo viejo, NO se crea el nuevo (nunca dos espejos a la vez)",
          rc10 == 1 and not reglas_creadas(r10), (rc10, hechas10))
    check("  y se para ahi: ni el fasttrack ni nada de lo que quedaba",
          hechas10[-1] == "/ip/firewall/mangle/set" and "/ip/firewall/filter/set" not in hechas10
          and "Se para aqui" in out10, (hechas10, out10[-300:]))
    r11 = Router(mangle=[dict(viejo)])
    r11.falla = "/ip/firewall/mangle/add"            # la primera regla nueva falla
    rc11, out11 = correr_salida(r11, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    adds = [c for c, _a in r11.ordenes if c == "/ip/firewall/mangle/add"]
    check("si falla la primera regla nueva, no se intentan las siguientes", rc11 == 1 and len(adds) == 1,
          (rc11, [c for c, _a in r11.ordenes]))
    r12 = Router(mangle=[dict(viejo)], lista=[{"list": "ids-vigilados", "address": "10.20.0.0/16"}])
    r12.falla = "/export"                            # sin respaldo...
    rc12, out12 = correr_salida(r12, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    tocadas = [c for c, _a in r12.ordenes if not c.endswith("/print") and c != "/export"]
    check("si el /export de respaldo falla, no se toca NADA del router",
          rc12 == 1 and tocadas == [] and "no se toca nada" in out12, (rc12, tocadas, out12[-300:]))
    r13 = Router(mangle=[dict(x, **{".id": "*%d" % (i + 1), "action": "sniff-tzsp"})
                         for i, x in enumerate(reglas_creadas(r8))],
                 lista=[{"list": "ids-vigilados", "address": "10.20.0.0/16"}],
                 filtro=[{".id": "*9", "action": "fasttrack-connection", "src-address-list": "!ids-vigilados"}])
    rc13, out13 = correr_salida(r13, tmp2, "-e", "vpn", "-r", "10.20.0.0/16", "--sin-registrar")
    check("  (un router ya al dia sigue saliendo con exito)", rc13 == 0, (rc13, out13[-300:]))

    # --- la clave tal cual (hallazgo 10): espacios o comillas en los bordes son parte de ella --
    for linea, esperada in (('PASS=" con espacios "\n', " con espacios "), ("PASS=acaba-en-comilla'\n", "acaba-en-comilla'"),
                            ("PASS='entre simples'\n", "entre simples"), ("PASS=sin comillas \r\n", "sin comillas "),
                            ('PASS=""doble""\n', '"doble"')):
        f = os.path.join(tmp2, "cred-clave")
        io.open(f, "w", encoding="utf-8", newline="").write("HOST=100.64.0.2\nUSER=ids\n" + linea)
        ns = {"__name__": "prueba"}
        exec(compile(PROG, "<mkinit>", "exec"), ns)
        with contextlib.redirect_stdout(io.StringIO()):
            leida = ns["leer_credenciales"](f)["PASS"]
        check("clave %r -> %r (solo se quita un par de comillas que la envuelva y el fin de linea)"
              % (linea.rstrip("\r\n"), esperada), leida == esperada, leida)

    # --- api-ssl sin huella previa: antes moria con NameError (guardar_mk no existe aqui) ----
    tmp3 = tempfile.mkdtemp()
    _j = SRC.index("cat > /usr/local/bin/suricata-dashboard <<'DASH'")
    dash = os.path.join(tmp3, "suricata-dashboard")
    io.open(dash, "w", encoding="utf-8").write(SRC[_j:].split("\n", 1)[1].split("\nDASH\n", 1)[0])
    ns = {"__name__": "prueba"}
    exec(compile(PROG, "<mkinit>", "exec"), ns)
    ns["DASHBOARD"] = dash
    api = ns["cliente_api"]()

    class SockTLS(object):
        def getpeercert(self, binary_form=False):
            return b"certificado-del-router"

        def settimeout(self, t):
            pass

        def close(self):
            pass
    api["_mk_tls_wrap"] = lambda host, port, timeout: SockTLS()
    api["_mk_send"] = lambda s_, palabras: None
    api["_mk_reply"] = lambda s_: (True, [], "")
    try:
        api["mk_conectar"]({"HOST": "100.64.0.2", "PORT": "8729", "TLS": "1", "USER": "ids", "PASS": "x"})
        conecto = True
    except Exception as ex:
        conecto = ex
    check("api-ssl sin huella previa: conecta (el cliente del panel no revienta fuera del panel)",
          conecto is True, conecto)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
