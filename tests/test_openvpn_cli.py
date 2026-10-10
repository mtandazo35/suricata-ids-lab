# -*- coding: utf-8 -*-
"""/root/openvpn.sh sin menu: las ordenes que usa el panel (Ajustes > VPN).

El operador no tiene que entrar por consola: la web crea usuarios y redes llamando al
script. Se ejecuta el script REAL (el que va embebido en el instalador) con todo bajo un
directorio temporal (OVPN_RAIZ) y los comandos del sistema simulados.

Lo que se protege:
  - --usuario: crea el usuario con la siguiente IP libre del tunel y da su comando
    ovpn-client (v7 y v6) en salida CLAVE=valor, sin pantallas;
  - --redes: rutas.sh + iroute, reinicia OpenVPN solo si agrego algo; repetida, no;
  - --quitar-redes: quita su linea, su iroute y la ruta viva, solo si es de ese usuario;
  - --borrar: sus redes, su archivo y su cuenta... y NUNCA una cuenta real del servidor
    (solo borra la cuenta si es de las que crea el script: sin shell y con su comentario);
  - --instalar no reinstala encima de un servidor que ya existe.
"""
import os
import re
import stat
import subprocess
import sys
import tempfile

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(RAIZ, "install-suricata.sh"), encoding="utf-8").read()
SCRIPT = SRC.split("<<'OVPNSH'\n", 1)[1].split("\nOVPNSH\n", 1)[0] + "\n"

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def posix(p):
    return ("/" + p[0].lower() + p[2:]) if len(p) > 2 and p[1] == ":" else p


def ejecutable(ruta, texto):
    open(ruta, "w", encoding="utf-8", newline="\n").write(texto)
    os.chmod(ruta, os.stat(ruta).st_mode | stat.S_IEXEC)


def entorno():
    td = tempfile.mkdtemp().replace("\\", "/")
    b = td + "/bin"
    os.makedirs(b)
    os.makedirs(td + "/raiz")
    open(td + "/passwd", "w").close()
    log = td + "/sistema.log"
    pw = td + "/passwd"
    ejecutable(b + "/systemctl", '#!/bin/sh\necho "systemctl $*" >> "%s"\n' % log)
    ejecutable(b + "/ip", '#!/bin/sh\necho "ip $*" >> "%s"\n' % log)
    ejecutable(b + "/userdel", '#!/bin/sh\necho "userdel $*" >> "%s"\n' % log)
    ejecutable(b + "/chpasswd", '#!/bin/sh\ncat > /dev/null\n')
    ejecutable(b + "/openvpn", '#!/bin/sh\nexit 0\n')
    ejecutable(b + "/curl", '#!/bin/sh\nexit 1\n')
    ejecutable(b + "/wget", '#!/bin/sh\nexit 1\n')
    ejecutable(b + "/useradd", '#!/bin/sh\nfor u; do :; done\n'
               'echo "$u:x:1000:1000:OpenVPN user:/nonexistent:/usr/sbin/nologin" >> "%s"\n' % pw)
    ejecutable(b + "/id", '#!/bin/sh\nfor u; do :; done\ngrep -q "^$u:" "%s"\n' % pw)
    ejecutable(b + "/getent", '#!/bin/sh\ngrep "^$2:" "%s"\n' % pw)
    # 'install -d -m 0700' falla en Windows al cambiar permisos en el temporal (en Linux no):
    # para los directorios basta un mkdir -p; el resto, el install de verdad
    ejecutable(b + "/install", '#!/bin/sh\nd=0\nfor a; do [ "$a" = "-d" ] && d=1; done\n'
               'if [ $d = 1 ]; then for a; do case "$a" in -*|0[0-7]*) ;; *) mkdir -p "$a";; esac; done; exit 0; fi\n'
               'exec /usr/bin/install "$@"\n')
    open(td + "/openvpn.sh", "w", encoding="utf-8", newline="\n").write(SCRIPT)
    return td


def correr(td, *args):
    env = dict(os.environ, OVPN_RAIZ=td + "/raiz", PATH=posix(td) + "/bin:" + os.environ.get("PATH", ""))
    cmd = 'export PATH="%s/bin:$PATH"; bash "%s/openvpn.sh" "$@"' % (posix(td), td)
    return subprocess.run(["bash", "-c", cmd, "x"] + list(args), capture_output=True, text=True,
                          encoding="utf-8", env=env)


def leer(ruta):
    try:
        return open(ruta, encoding="utf-8").read()
    except OSError:
        return ""


def main():
    td = entorno()
    ccd = td + "/raiz/etc/openvpn/open-vpn"
    rutas = ccd + "/rutas.sh"
    log = td + "/sistema.log"

    r = correr(td, "--usuario")
    kv = dict(re.findall(r"(?m)^([A-Z0-9]+)=(.*)$", r.stdout))
    u1 = kv.get("USUARIO", "")
    check("--usuario: crea el usuario sin pantallas y da CLAVE=valor",
          r.returncode == 0 and re.match(r"^vpn[0-9a-f]{12}$", u1) and len(kv.get("CLAVE", "")) == 32, (r.stdout, r.stderr[-300:]))
    check("  con la primera IP libre del tunel (.1 es el servidor)", kv.get("IPVPN") == "100.64.0.2", kv)
    check("  y el comando ovpn-client para v7 y v6 con su usuario y clave",
          kv.get("MT7", "").startswith("/interface ovpn-client add ") and "protocol=tcp" in kv.get("MT7", "")
          and "cipher=aes256-cbc" in kv["MT7"] and ("user=%s " % u1) in kv["MT7"] and ("password=%s " % kv["CLAVE"]) in kv["MT7"]
          and "cipher=aes256 " in kv.get("MT6", ""), kv)
    check("  su archivo con la IP fija", "ifconfig-push 100.64.0.2 255.255.255.0" in leer(ccd + "/" + u1), leer(ccd + "/" + u1))
    r2 = correr(td, "--usuario")
    kv2 = dict(re.findall(r"(?m)^([A-Z0-9]+)=(.*)$", r2.stdout))
    u2 = kv2.get("USUARIO", "")
    check("  el segundo MikroTik recibe la siguiente IP", kv2.get("IPVPN") == "100.64.0.3", kv2)

    open(log, "w").close()
    r = correr(td, "--redes", u1, "10.20.0.0/16", "192.168.50.0/24")
    check("--redes: agrega las redes", r.returncode == 0
          and "/sbin/ip route replace 10.20.0.0/16 via 100.64.0.2 # %s 10.20.0.0/16" % u1 in leer(rutas)
          and "iroute 10.20.0.0 255.255.0.0" in leer(ccd + "/" + u1)
          and "iroute 192.168.50.0 255.255.255.0" in leer(ccd + "/" + u1), (r.stdout, r.stderr[-300:]))
    check("  y reinicia OpenVPN para aplicarlas", "restart openvpn-server@server" in leer(log), leer(log))
    open(log, "w").close()
    r = correr(td, "--redes", u1, "10.20.0.0/16")
    check("  repetida: no se duplica ni reinicia",
          leer(rutas).count("10.20.0.0/16 via") == 1 and "restart" not in leer(log), leer(log))
    r = correr(td, "--redes", u2, "172.30.0.0/16")
    check("  otro MikroTik, otras redes", "# %s 172.30.0.0/16" % u2 in leer(rutas), leer(rutas))

    open(log, "w").close()
    r = correr(td, "--quitar-redes", u2, "10.20.0.0/16")
    check("--quitar-redes: una red de OTRO usuario no se quita",
          "# %s 10.20.0.0/16" % u1 in leer(rutas) and "restart" not in leer(log), (r.stdout, leer(rutas)))
    r = correr(td, "--quitar-redes", u1, "10.20.0.0/16")
    check("  la suya si: su linea, su iroute y la ruta viva",
          r.returncode == 0 and "10.20.0.0/16" not in leer(rutas) and "iroute 10.20.0.0 " not in leer(ccd + "/" + u1)
          and "ip route del 10.20.0.0/16" in leer(log) and "restart openvpn-server@server" in leer(log),
          (r.stdout, r.stderr[-200:], leer(log)))
    check("  sin tocar el resto", "# %s 192.168.50.0/24" % u1 in leer(rutas) and "# %s 172.30.0.0/16" % u2 in leer(rutas), leer(rutas))

    open(log, "w").close()
    r = correr(td, "--borrar", u1)
    check("--borrar: quita sus redes (y la ruta viva), su archivo y su cuenta",
          r.returncode == 0 and ("# %s " % u1) not in leer(rutas) and not os.path.exists(ccd + "/" + u1)
          and "ip route del 192.168.50.0/24" in leer(log) and ("userdel %s" % u1) in leer(log),
          (r.stdout, r.stderr[-200:], leer(log)))
    check("  sin tocar al otro MikroTik", "# %s 172.30.0.0/16" % u2 in leer(rutas) and os.path.exists(ccd + "/" + u2), "")

    # una cuenta REAL del servidor que se llama como un usuario de la VPN: no se borra
    open(ccd + "/operador1", "w").write("ifconfig-push 100.64.0.9 255.255.255.0\n")
    with open(td + "/passwd", "a") as f:
        f.write("operador1:x:1001:1001:Operador del ISP:/home/operador1:/bin/bash\n")
    open(log, "w").close()
    r = correr(td, "--borrar", "operador1")
    check("--borrar NUNCA borra una cuenta real del servidor (con shell y otro comentario)",
          "userdel" not in leer(log) and "no la creo este script" in (r.stdout + r.stderr), (r.stdout, leer(log)))

    open(td + "/raiz/etc/openvpn/server/server.conf", "w").write("port 1194\n") if os.path.isdir(td + "/raiz/etc/openvpn/server") \
        else (os.makedirs(td + "/raiz/etc/openvpn/server"), open(td + "/raiz/etc/openvpn/server/server.conf", "w").write("port 1194\n"))
    r = correr(td, "--instalar")
    check("--instalar no reinstala encima de un servidor que ya existe",
          r.returncode != 0 and "ya esta instalado" in (r.stdout + r.stderr), (r.returncode, r.stderr[-200:]))
    r = correr(td, "--borrar", "NO VALIDO")
    check("un usuario con caracteres raros se rechaza", r.returncode != 0, r.returncode)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
