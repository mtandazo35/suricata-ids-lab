# -*- coding: utf-8 -*-
"""El instalador de OpenVPN para el tunel del MikroTik, que el instalador deja en /root.

De donde sale: los sensores reciben el espejo por VPN y el sensor es el servidor
OpenVPN. En 205.235.2.149 el operador lo monto con su /root/openvpn.sh (menu: instalar
el servidor, un usuario por MikroTik, redes de clientes). Ahora lo deja el instalador
en cada caja, tal cual.

Lo que se protege (ejecutando el trozo REAL con /root redirigido):
  - caja nueva: queda /root/openvpn.sh identico (misma huella SHA256), ejecutable;
  - si ya estaba igual, no se respalda nada; si habia uno DISTINTO, se respalda antes;
  - el script es bash valido;
  - el servidor que monta es compatible con RouterOS: TCP, AES-256-CBC, SHA1, sin
    tls-crypt/tls-auth (RouterOS no los soporta);
  - en modo VPN sin tunel, el resumen dice como montarlo con /root/openvpn.sh.
"""
import hashlib
import os
import re
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


ini = SRC.index("# ------------------------------------------- instalador de OpenVPN para el tunel")
fin = SRC.index("# ------------------------------------------- estoy leyendo trafico?", ini)
BLOQUE = SRC[ini:fin]
SHA = re.search(r'OVPN_SHA="([0-9a-f]{64})"', BLOQUE).group(1)
SCRIPT = BLOQUE.split("<<'OVPNSH'\n", 1)[1].split("\nOVPNSH\n", 1)[0] + "\n"


def correr(root):
    # solo las rutas del instalador, NO el contenido del script (cambiaria su huella)
    cab_, cuerpo = BLOQUE.split("<<'OVPNSH'\n", 1)
    guion, cola = cuerpo.split("\nOVPNSH\n", 1)
    t = (cab_.replace("/root/", root + "/") + "<<'OVPNSH'\n" + guion + "\nOVPNSH\n"
         + cola.replace("/root/", root + "/"))
    cab = "set -euo pipefail\nok(){ echo \"OK $*\"; }\nwarn(){ echo \"WARN $*\"; }\nSTAMP=20261010-170000\n"
    # por stdin, como el curl | bash real (y en Windows una linea de comandos no pasa de
    # 32 KB: el script embebido ya ocupa 17)
    # en UTF-8 explicito: el script lleva tildes y en Windows el texto saldria en cp1252,
    # con otros bytes y otra huella (en el servidor, curl | bash pasa los bytes tal cual)
    return subprocess.run(["bash", "-s"], input=cab + t, capture_output=True, text=True,
                          encoding="utf-8")


def main():
    check("la huella declarada es la del script embebido",
          hashlib.sha256(SCRIPT.encode("utf-8")).hexdigest() == SHA, SHA)

    root = tempfile.mkdtemp().replace("\\", "/")
    r = correr(root)
    dest = root + "/openvpn.sh"
    check("caja nueva: el trozo real corre sin errores", r.returncode == 0, r.stderr[-300:])
    check("  deja /root/openvpn.sh identico (misma huella)",
          os.path.isfile(dest) and hashlib.sha256(open(dest, "rb").read()).hexdigest() == SHA, "")
    check("  y no deja temporales", not [f for f in os.listdir(root) if f.startswith(".openvpn.sh.")], os.listdir(root))

    r2 = correr(root)
    check("si ya estaba igual, no se respalda nada",
          r2.returncode == 0 and not [f for f in os.listdir(root) if ".bak-" in f], os.listdir(root))

    open(dest, "w", encoding="utf-8", newline="\n").write("#!/bin/bash\necho version del operador\n")
    r3 = correr(root)
    bak = root + "/openvpn.sh.bak-20261010-170000"
    check("si habia uno DISTINTO, se respalda antes de sustituirlo",
          r3.returncode == 0 and os.path.isfile(bak) and "version del operador" in open(bak).read()
          and hashlib.sha256(open(dest, "rb").read()).hexdigest() == SHA, r3.stdout + r3.stderr)

    rn = subprocess.run(["bash", "-n", dest], capture_output=True, text=True)
    check("el script es bash valido", rn.returncode == 0, rn.stderr)

    conf = SCRIPT.split('cat > "$SERVER_DIR/server.conf" <<EOF_CONF', 1)[1].split("EOF_CONF", 1)[0]
    check("el servidor es compatible con RouterOS: sin tls-crypt ni tls-auth",
          "tls-crypt" not in conf and "tls-auth" not in conf, conf)
    check("  TCP, AES-256-CBC y SHA1 (RouterOS v6 y v7)",
          'PROTOCOL="tcp"' in SCRIPT and "cipher AES-256-CBC" in conf and 'OPENVPN_AUTH_DIGEST="SHA1"' in SCRIPT, "")
    check("  y da el comando ovpn-client para v6 y v7",
          "ROUTEROS v7" in SCRIPT and "ROUTEROS v6" in SCRIPT and "/interface ovpn-client" in SCRIPT, "")

    check("en modo VPN sin tunel, el resumen dice como montarlo",
          'bash /root/openvpn.sh   -> 1) instala el servidor' in SRC
          and '[ "$ESPEJO_DONDE" = "vpn" ] && [ -z "$ESPEJO_IP" ]' in SRC, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
