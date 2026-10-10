# -*- coding: utf-8 -*-
"""Modo VPN: el sensor solo recibe por el tunel.

De donde sale (205.235.2.149, 2026-10-10): instalado con -t en modo VPN, pero el receptor
escuchaba en 0.0.0.0:37008 sin firewall (solo filtraba por IP de origen, que en UDP se
falsifica), el panel (HTTP plano) y EveBox abiertos a internet, y las reglas que se
imprimian para el MikroTik mandaban el espejo a la IP PUBLICA: por internet, no por la VPN.

Lo que se protege (ejecutando los trozos REALES con ip/nft/systemctl simulados):
  - con la VPN arriba, el espejo va a la IP del sensor DENTRO del tunel;
  - con la VPN caida, se avisa y NO se usa la publica (queda un hueco evidente);
  - el firewall generado descarta por la interfaz de internet el espejo, la web y LLMNR,
    con contador; abre la web solo a -a; NO toca SSH;
  - en modo local se quita ese firewall (el espejo llega por la LAN);
  - suricata-espejo dice cuando el espejo llega por internet y lo descarta el firewall, y
    el recorte configurado aunque aun no haya llegado nada.
"""
import ast
import os
import stat
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def posix(p):
    """Ruta para el PATH de bash: en Windows (Git Bash) "C:/x" tiene que ser "/c/x", porque
    los ':' separan entradas del PATH."""
    return ("/" + p[0].lower() + p[2:]) if len(p) > 2 and p[1] == ":" else p


def ejecutable(ruta, texto):
    open(ruta, "w", encoding="utf-8", newline="\n").write(texto)
    os.chmod(ruta, os.stat(ruta).st_mode | stat.S_IEXEC)


def entorno(ruta_get):
    """bin/ con ip, nft, systemctl y apt-get de mentira. ruta_get = salida de 'ip route get'."""
    td = tempfile.mkdtemp().replace("\\", "/")
    b = td + "/bin"
    os.makedirs(b)
    ejecutable(b + "/ip", "#!/bin/sh\n"
               "case \"$*\" in\n"
               "  *'route show to default'*) echo 'default via 10.0.0.4 dev eth0 proto static onlink' ;;\n"
               "  *'route get'*) echo '%s' ;;\n"
               "esac\n" % ruta_get)
    ejecutable(b + "/nft", "#!/bin/sh\n[ \"$1\" = \"-f\" ] && cat > \"%s/ruleset.nft\"\nexit 0\n" % td)
    ejecutable(b + "/systemctl", "#!/bin/sh\necho \"$*\" >> \"%s/systemctl.log\"\nexit 0\n" % td)
    ejecutable(b + "/apt-get", "#!/bin/sh\nexit 0\n")
    return td


def trozo(td):
    ini = SRC.index("# A donde manda el MikroTik el espejo.")
    k = SRC.index('ok "Modo local: quitado el firewall del modo VPN', ini)
    fin = SRC.index("\nfi\n", k) + 4
    t = SRC[ini:fin]
    t = t.replace("/usr/local/sbin/suricata-ids-fw", td + "/suricata-ids-fw")
    t = t.replace("/etc/systemd/system/suricata-ids-fw.service", td + "/suricata-ids-fw.service")
    return t


def correr(td, modo="vpn", gestion="", web=1):
    cab = ("set -euo pipefail\nexport PATH=\"%s/bin:$PATH\"\n"
           "ok(){ echo \"OK $*\"; }\nwarn(){ echo \"WARN $*\"; }\n"
           "TZSP=1; ESPEJO_DONDE=%s; MIRROR_SRC=100.64.0.2; PUB_IP=205.235.2.149\n"
           "TZSP_PORT=37008; WEB=%d; WEB_PORT=5636; DASH_PORT=5637; GESTION='%s'\n" % (posix(td), modo, web, gestion))
    pie = '\necho "ESPEJO_IP=$ESPEJO_IP"\necho "ESPEJO_IP_TXT=$ESPEJO_IP_TXT"\n'
    return subprocess.run(["bash", "-c", cab + trozo(td) + pie], capture_output=True, text=True)


def valor(out, k):
    return next((l.split("=", 1)[1] for l in out.splitlines() if l.startswith(k + "=")), None)


def main():
    # ---------- VPN arriba ----------
    td = entorno("100.64.0.2 dev tun0 src 100.64.0.1 uid 0")
    r = correr(td)
    check("VPN arriba: el trozo real corre sin errores", r.returncode == 0, r.stderr[-300:])
    check("  el espejo va a la IP del sensor DENTRO del tunel (no a la publica)",
          valor(r.stdout, "ESPEJO_IP") == "100.64.0.1", r.stdout)
    check("  se genera el firewall y su servicio",
          os.path.isfile(td + "/suricata-ids-fw") and os.path.isfile(td + "/suricata-ids-fw.service"), "")
    check("  y se habilita/arranca", "enable suricata-ids-fw" in open(td + "/systemctl.log").read()
          and "restart suricata-ids-fw" in open(td + "/systemctl.log").read(), "")

    # el firewall generado, ejecutado
    rf = subprocess.run(["bash", "-c", 'export PATH="%s/bin:$PATH"; sh "%s/suricata-ids-fw" start' % (posix(td), td)],
                        capture_output=True, text=True)
    rs = open(td + "/ruleset.nft", encoding="utf-8").read() if os.path.exists(td + "/ruleset.nft") else ""
    check("el firewall corre y carga una tabla propia", rf.returncode == 0 and "table inet suricata_ids" in rs, (rf.stderr, rs))
    check("  descarta el espejo que llega por internet (eth0), con contador",
          'iifname "eth0" udp dport 37008 counter drop' in rs, rs)
    check("  descarta el panel y EveBox desde internet",
          'iifname "eth0" tcp dport { 5637, 5636 } counter drop' in rs, rs)
    check("  y LLMNR", "th dport 5355 drop" in rs, rs)
    check("  NO toca SSH", "dport 22" not in rs and " 22 " not in rs, rs)
    check("  sin -a no abre la web a nadie de fuera (ninguna regla accept; la politica es accept)",
          "} accept" not in rs and " accept comment" not in rs, rs)

    # con -a: la web solo desde esa red
    td2 = entorno("100.64.0.2 dev tun0 src 100.64.0.1")
    correr(td2, gestion="203.0.113.0/24,198.51.100.7")
    subprocess.run(["bash", "-c", 'export PATH="%s/bin:$PATH"; sh "%s/suricata-ids-fw" start' % (posix(td2), td2)])
    rs2 = open(td2 + "/ruleset.nft", encoding="utf-8").read()
    check("con -a: la web se abre SOLO desde esas redes, antes del drop",
          'ip saddr { 203.0.113.0/24, 198.51.100.7 } tcp dport { 5637, 5636 } accept' in rs2
          and rs2.index("accept") < rs2.index("tcp dport { 5637, 5636 } counter drop"), rs2)

    # ---------- con UFW activo: la web se abre por el tunel, y solo por el tunel ----------
    # La tabla propia (policy accept, drop solo por la WAN) no cierra el tunel; UFW (deny por
    # defecto) si: solo abria la web a -a, y "entra por la VPN" no entraba nadie.
    def con_ufw(td_):
        ejecutable(td_ + "/bin/ufw", "#!/bin/sh\n"
                   "if [ \"$1\" = status ]; then echo 'Status: active'; cat \"%s/ufw.rules\" 2>/dev/null; exit 0; fi\n"
                   "echo \"$*\" >> \"%s/ufw.log\"\nexit 0\n" % (td_, td_))
    td5 = entorno("100.64.0.2 dev tun0 src 100.64.0.1 uid 0")
    con_ufw(td5)
    r5 = correr(td5)
    ufw5 = open(td5 + "/ufw.log").read() if os.path.exists(td5 + "/ufw.log") else ""
    check("UFW activo: se abre la web (panel y EveBox) en la interfaz del tunel",
          r5.returncode == 0 and "allow in on tun0 to any port 5637 proto tcp" in ufw5
          and "allow in on tun0 to any port 5636 proto tcp" in ufw5, (ufw5, r5.stdout[-300:], r5.stderr[-300:]))
    check("  y en ningun otro sitio: ni a internet ni a todo el mundo",
          all(" in on tun0 " in l for l in ufw5.splitlines() if "port 5637" in l or "port 5636" in l), ufw5)
    td6 = entorno("100.64.0.2 dev tun0 src 100.64.0.1 uid 0")
    con_ufw(td6)
    open(td6 + "/ufw.rules", "w").write("5637/tcp on tun0           ALLOW       Anywhere\n")
    correr(td6)
    ufw6 = open(td6 + "/ufw.log").read() if os.path.exists(td6 + "/ufw.log") else ""
    check("  re-ejecutar no la duplica", "port 5637" not in ufw6 and "port 5636" in ufw6, ufw6)
    td7 = entorno("100.64.0.2 via 10.0.0.4 dev eth0 src 198.51.100.149")
    con_ufw(td7)
    r7 = correr(td7)
    ufw7 = open(td7 + "/ufw.log").read() if os.path.exists(td7 + "/ufw.log") else ""
    check("  con la VPN caida no se abre nada (no hay tunel) y se avisa",
          "port 5637" not in ufw7 and "la web no se abre por el tunel" in r7.stdout, (ufw7, r7.stdout[-300:]))

    # ---------- VPN caida ----------
    td3 = entorno("100.64.0.2 via 10.0.0.4 dev eth0 src 205.235.2.149")
    r3 = correr(td3)
    check("VPN caida: se avisa", "aun no se alcanza por un tunel" in r3.stdout, r3.stdout)
    check("  y NO se usa la IP publica: queda un hueco evidente",
          valor(r3.stdout, "ESPEJO_IP") == "" and valor(r3.stdout, "ESPEJO_IP_TXT") == "<IP-del-sensor-en-la-VPN>", r3.stdout)

    # ---------- local: se quita ----------
    td4 = entorno("10.87.87.1 dev eth0 src 10.87.87.3")
    open(td4 + "/suricata-ids-fw.service", "w").write("x")
    open(td4 + "/suricata-ids-fw", "w").write("x")
    r4 = correr(td4, modo="local")
    check("modo local: se quita el firewall del modo VPN (el espejo llega por la LAN)",
          r4.returncode == 0 and not os.path.exists(td4 + "/suricata-ids-fw.service")
          and "disable --now suricata-ids-fw" in open(td4 + "/systemctl.log").read(), r4.stdout + r4.stderr)

    # ---------- donde se usa ----------
    check("las reglas impresas para el router usan la IP del tunel (las 3)",
          SRC.count("sniff-target=${ESPEJO_IP_TXT}") == 3 and "sniff-target=${PUB_IP" not in SRC, "")
    check("-k configura el router con la IP del tunel", '-s "${ESPEJO_IP:-}"' in SRC, "")

    # ---------- suricata-espejo ----------
    i = SRC.index("cat > /usr/local/bin/suricata-espejo <<'ESPEJO'")
    ESP = SRC[i:].split("\n", 1)[1].split("\nESPEJO\n", 1)[0]
    arbol = ast.parse(ESP)
    salidas = {}

    class Sub(object):
        DEVNULL = None
        CalledProcessError = subprocess.CalledProcessError

        @staticmethod
        def check_output(cmd, **k):
            return salidas[cmd[0]].encode()
    ns = {"subprocess": Sub, "MUDO": 600, "DESPERDICIO_AVISO": 0.5}
    for n in arbol.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("fuera_del_tunel", "recorte_configurado", "veredicto"):
            exec(ast.get_source_segment(ESP, n), ns)
    salidas["nft"] = ('table inet suricata_ids {\n chain input {\n'
                      '  iifname "eth0" udp dport 37008 counter packets 4321 bytes 99 drop comment "x"\n }\n}\n')
    salidas["systemctl"] = "Environment=TZSP_PORT=37008 TZSP_OUT_IF=ids-in TZSP_ALLOW=100.64.0.2 TZSP_BYTES=10000\n"
    check("suricata-espejo lee los paquetes descartados por llegar fuera de la VPN",
          ns["fuera_del_tunel"]() == 4321, ns["fuera_del_tunel"]())
    check("  y el recorte configurado aunque no haya llegado nada", ns["recorte_configurado"]() == 10000, "")
    niv, txt = ns["veredicto"](True, True, {}, {}, {}, 0.0, 0.0, None, 0, 5, 4321)
    check("  si el espejo llega por internet, lo dice y que hacer (sniff-target = IP del tunel, o -e local)",
          niv == "rojo" and "por INTERNET" in txt and "DENTRO del tunel" in txt and "-e local" in txt, txt)
    niv2, txt2 = ns["veredicto"](True, True, {}, {}, {}, 0.0, 0.0, None, 0, 5, 0)
    check("  sin descartados, el aviso de siempre", "Nadie esta espejando" in txt2, txt2)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
