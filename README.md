# suricata-ids-lab

Instalador de **Suricata en modo IDS** con **interfaz web (EveBox)** para
**Debian 13 (Trixie)** o Debian 12. Un solo comando en cualquier VPS o VM y en
minutos tienes alertas, flujos, DNS, TLS y HTTP visibles en el navegador.

> Debian 12 (bookworm) trae Suricata 6.0.x y Debian 13 (trixie) 7.0.x. El
> instalador funciona igual en ambos, pero solo se ha verificado en Debian 13.

Objetivo: detectar **clientes/CPEs infectados que escanean o atacan hacia
afuera** (el caso real que motiva esto), antes de llevarlo a un MikroTik de
produccion. Sin Elastic ni dependencias externas: EveBox lee `eve.json` y guarda
en SQLite local.

## ⚡ Quick install (one-liner)

En una VM/VPS Debian 13/12 limpia, como root:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash
```

Al terminar imprime la **URL de la web, el usuario `admin` y la clave generada**.
Entra con el navegador a `https://<IP>:5636` (certificado autofirmado: acepta la
advertencia).

Opciones (se pasan tras `bash -s --`):

| Opcion | Que hace | Default |
|---|---|---|
| `-i IFACE` | interfaz a escuchar | la de la ruta default |
| `-n CIDR[,CIDR]` | `HOME_NET` (admite varias redes separadas por coma; con `-t` pasa aqui las redes de tus clientes) | red de la interfaz |
| `-p PUERTO` | puerto de la web | `5636` |
| `-P CLAVE` | clave del usuario web `admin` | aleatoria (se muestra al final) |
| `-t` | **receptor TZSP** (UDP 37008) para espejo MikroTik | apagado |
| `-W` | **sin web**, solo Suricata + logs | web activada |

```bash
# forzar interfaz y red
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -i ens18 -n 10.0.0.0/24

# web en otro puerto y con clave propia
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -p 8443 -P 'MiClaveSegura'

# solo IDS, sin web
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -W
```

Script de prueba de deteccion (se guarda en `/root`, segun convencion):

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/test-alerts.sh -o /root/test-alerts.sh && chmod +x /root/test-alerts.sh && sudo /root/test-alerts.sh
```

> La imagen `genericcloud` de Debian no trae `curl`: antes `apt-get update && apt-get install -y curl`.

## Interfaz web (EveBox)

Suricata no trae web propia; el instalador integra [EveBox](https://evebox.org):

- Se instala el **`.deb` oficial** (verificado por SHA256) descargado del pool de
  evebox.org. No se usa su repo apt porque su llave lleva firma SHA1 y Debian 13
  la rechaza. Se toma la version vigente del indice; si no responde, se usa la
  fijada en el script (0.28.0).
- **SQLite local** en `/var/lib/evebox`, retencion 7 dias y tope 5 GB.
- **HTTPS** con certificado autofirmado generado por EveBox y **login obligatorio**
  (usuario `admin`). La clave se crea antes del primer arranque; re-ejecutar el
  instalador **no** la cambia salvo que pases `-P`.
- Escucha en `0.0.0.0:5636`. Si UFW esta activo abre el puerto; si hay un firewall
  externo (nube, Proxmox, MikroTik) abrelo tu.
- El servicio corre como usuario `evebox`; el instalador le da acceso de lectura a
  `/var/log/suricata` via grupo + setgid.

```bash
# estado / logs
systemctl status evebox
journalctl -u evebox -f
```

Config: `/etc/evebox/evebox.yaml` (backup con fecha en cada ejecucion).

### Cambiar la clave de `admin`

**Opcion 1 (recomendada): re-ejecutar el instalador con `-P`.** Es idempotente:
no reinstala nada, cambia la clave del usuario existente y verifica que el
servicio levante. Al final imprime la URL, el usuario y la clave nueva.

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -P 'TuClaveNueva'
```

**Opcion 2: el ayudante que deja el instalador**, sin preguntas:

```bash
evebox-passwd admin 'TuClaveNueva'
```

**Opcion 3: el CLI de EveBox** (interactivo, pide la clave dos veces):

```bash
runuser -u evebox -- evebox -D /var/lib/evebox -C /var/lib/evebox config users passwd admin
```

> Por que existe el ayudante: `evebox config users passwd` exige un TTY (falla con
> "The input device is not a TTY" desde scripts) y `users rm admin` falla por clave
> foranea en cuanto el usuario tiene sesiones web, asi que no se puede borrar y
> recrear. `evebox-passwd` le da un pseudo-terminal y responde las dos preguntas.
> Ejecuta siempre el CLI con `runuser -u evebox`: como root, `config.sqlite` puede
> quedar con dueño root y el servicio deja de poder escribirla.

**Clave perdida:** la opcion 1 o la 2 la reemplazan sin necesidad de conocer la
anterior.

## Montaje del lab

1. En Proxmox `10.0.0.2` crea una VM **Debian 13** (2 vCPU / 4–8 GB RAM basta para
   el lab; ver tabla de RAM abajo). Conectala a una `vmbr` aislada.
2. Copia este repo a la VM (a `/root/`, segun convencion) y ejecuta:

   ```bash
   chmod +x install-suricata.sh test-alerts.sh test-tzsp.sh
   sudo ./install-suricata.sh
   ```

   Auto-detecta la interfaz por la ruta default y fija `HOME_NET` a su red.
   Para forzar valores:

   ```bash
   sudo ./install-suricata.sh -i ens18 -n 10.0.0.0/24
   ```

3. Confirma que detecta:

   ```bash
   sudo ./test-alerts.sh            # DNS .top + User-Agent 'wget 3.0' + nmap al gateway
   tail -f /var/log/suricata/fast.log
   ```

   Las firmas de prueba son `ET DNS Query to a *.top domain` y `ET ADWARE_PUP Fake
   Wget User-Agent`; ambas vienen en ET Open. (El clasico testmynids.org ya no
   resuelve.) El trafico debe **salir por la interfaz** escuchada: lo que va por
   `lo` nunca lo ve el IDS.

## Que instala

- `suricata` + `suricata-update` (reglas **ET Open**) desde repos de Debian 13.
- **EveBox** (web) leyendo `eve.json` a SQLite, con auth y TLS. Ver seccion arriba.
- Con `-t`: **receptor TZSP** para espejo desde MikroTik. Ver seccion abajo.
- Modo **IDS pasivo AF_PACKET** sobre la interfaz elegida.
- `HOME_NET` = red de la interfaz (para que marque bien lo "saliente").
- **Offloads apagados** en la interfaz de captura (gro/lro/tso/gso/rx-gro-hw) con un
  drop-in de systemd: con ellos activos el kernel entrega tramas >1514 bytes y
  Suricata las descarta como `truncated packet` (visto en virtio/Proxmox).
- `memcap` conservador (512mb) — subir si aparecen `kernel_drops`.
- Servicio systemd habilitado. Backup de `suricata.yaml` con fecha.

## Ver alertas

```bash
# legible
tail -f /var/log/suricata/fast.log

# JSON filtrado: origen, destino, firma
tail -f /var/log/suricata/eve.json | \
  jq 'select(.event_type=="alert") | {src:.src_ip,dst:.dest_ip,sig:.alert.signature}'

# rendimiento / drops
grep -E 'kernel_drops|memcap' /var/log/suricata/stats.log
```

## RAM segun trafico espejeado

| Trafico | RAM |
|---|---|
| Lab / hasta ~200 Mbps | 4 GB |
| ~500 Mbps – 1 Gbps | 8 GB |
| 1–3 Gbps | 16 GB (subir `stream.memcap`/`flow.memcap`) |

En Suricata la RAM la mandan los `memcap`, no el disco. Vigila `memcap_drop` en
`stats.log`: mientras no aparezcan, no hace falta mas RAM.

## Espejo desde MikroTik (TZSP)

Para analizar el trafico real de tu red MikroTik hay que **espejarlo** hacia el
servidor. El camino sin hardware extra es **TZSP**: el router envuelve cada paquete
en UDP/37008 y lo manda al servidor. Suricata **no** entiende TZSP crudo (solo
genera `truncated packet`), asi que el instalador con `-t` monta un receptor:

```
MikroTik --TZSP UDP/37008--> tzsp-decap.py --trama Ethernet--> veth ids-in -> ids-mon --> Suricata
```

- `tzsp-decap.service`: desencapsulador en Python (stdlib), crea el par veth,
  reinyecta las tramas y loguea `rx/tx` cada 60 s en `journalctl -u tzsp-decap`.
- Suricata captura `ids-mon` como segunda interfaz af-packet, con
  `checksum-checks: no` y `stream.checksum-validation: no` (el trafico espejeado
  llega con checksums de offload rotos; sin esto todo seria `invalid checksum`).
- Abre `37008/udp` en UFW si esta activo. Si hay firewall externo, abrelo tu.

### Ajustes automaticos en modo espejo

Con `-t` el instalador aplica lo que hizo falta al conectar un MikroTik real
(~32k pps): sin esto el disco se llenaba y la deteccion moria a los pocos minutos.

- **veth `ids-in`/`ids-mon` con MTU 65535** y `block-size: 131072` en Suricata. El
  router agrega segmentos (GRO) y manda tramas de hasta ~22 kB; con MTU 1600 o 9000
  se perdian (`muy_grandes` en el log del receptor) y cada trama perdida es un hueco
  mas en el reensamblado.
- **Filtro BPF en la interfaz principal**: `not (udp port 37008 or fragmentos IP)`, para
  que Suricata no inspeccione el propio flujo TZSP (doble CPU, alertas `truncated`).
- **Memcaps segun la RAM real** (siempre, no solo con -t): reensamblado TCP 25 %,
  flow 6 %, stream 6 %, defrag 1.5 %. Con el valor fijo anterior (512 MB) el
  reensamblado se llenaba a los ~5 min y, como el memcap es global, Suricata dejaba de
  reensamblar **todo**, tambien el trafico propio: las firmas HTTP dejaban de disparar.
- **`stream.midstream: true` y `async-oneside: true`** (el espejo llega con perdidas y
  sesiones ya empezadas). Se insertan bajo `stream:`; en el yaml de Debian vienen
  comentadas.
- **Reglas de diagnostico interno fuera** via `/etc/suricata/disable.conf`: todas las
  `SURICATA *` (stream, decoder, quic, tls, http...; viven en 22 archivos
  `*-events.rules`). Con espejo asimetrico eran el 95 % de las alertas
  (`STREAM invalid ack`, `QUIC error on data`, `TLS handshake invalid length`).
- **Bypass de flujos cifrados**: `stream.bypass: true` + `tls.encryption-handling:
  bypass`, TCP establecido 600 -> 300 s y `reassembly.depth` 1 MB -> 512 kB. Sin esto
  el reensamblado crecia ~100 MB/min sin meseta reteniendo segmentos de flujos que
  nunca se iban a inspeccionar.
- **eve.json solo con `alert`, `http`, `tls`, `ssh`, `files` y `stats`**, que es lo que
  EveBox necesita, y el **DNS aparte en `dns.json`** (solo consultas). Con espejo real
  `flow` era el 76 % del volumen y `dns` el 15 % (15 MB/s = 1,3 TB/dia); EveBox
  (SQLite) ingiere ~600 eventos/s y se quedaba 30 min atrasado purgando en bucle.
  Para volver a activar un tipo, descomenta su linea en `outputs: eve-log: types:`.
- **Logrotate instalado y forzado**: cada hora (drop-in del timer), `maxsize 2G`,
  7 copias. Debian trae rotacion semanal sin tope y en una Debian minima ni siquiera
  viene el paquete `logrotate`. EveBox guarda sus datos aparte en SQLite (7 dias /
  5 GB), asi que truncar o rotar eve.json no borra lo que ya se ve en la web.

Cifras de referencia: ~32k pps espejeados, receptor Python sin descartes, Suricata con
8 hilos por interfaz y ~2 % de `kernel_drops` en una VM de 8 vCPU / 16 GB. Para mas
volumen, mirror por hardware (Opcion C). Vigila `tcp.reassembly_memuse` en
`stats.log`: si se pega al memcap, falta RAM.

### 1. Instalar el receptor

Pasa `-t` y en `-n` **las redes de tus clientes** (separadas por coma), para que
Suricata sepa que es "casa" y marque bien lo saliente:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -t -n 172.16.0.0/12,10.0.0.0/8
```

Probar sin MikroTik (manda una trama TZSP sintetica y espera la alerta):

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/test-tzsp.sh -o /root/test-tzsp.sh && chmod +x /root/test-tzsp.sh && sudo /root/test-tzsp.sh
```

### 2. Comandos en el MikroTik

Sustituye `IP_SURICATA` por la IP del servidor (la que imprime el instalador).

**Opcion A: todo el trafico de una interfaz** (`/tool sniffer` en modo streaming).
Elige la interfaz donde pasa el trafico de clientes (el bridge LAN o el ether WAN):

```routeros
/tool sniffer set streaming-enabled=yes streaming-server=IP_SURICATA filter-stream=yes filter-interface=bridge
/tool sniffer start
# el sniffer NO sobrevive al reinicio: arrancarlo con el scheduler
/system scheduler add name=sniffer-start start-time=startup on-event="/tool sniffer start"
# comprobar
/tool sniffer print
```

Filtros utiles para no espejar todo:

```routeros
# solo una red de clientes
/tool sniffer set filter-ip-address=172.16.10.0/24
# solo lo que sale hacia internet (reduce a la mitad): rx en el bridge LAN, tx si sniffas el ether WAN
/tool sniffer set filter-direction=rx
# solo DNS + HTTP + HTTPS
/tool sniffer set filter-port=53,80,443
```

**Opcion B: selectivo por regla de firewall** (`action=sniff-tzsp` en mangle).
Solo se espeja lo que matchea la regla; ideal para una red o un cliente concreto:

```routeros
/ip firewall mangle add chain=prerouting src-address=172.16.10.0/24 action=sniff-tzsp sniff-target=IP_SURICATA sniff-target-port=37008 passthrough=yes comment="espejo a Suricata"
# la respuesta (trafico de vuelta al cliente)
/ip firewall mangle add chain=forward dst-address=172.16.10.0/24 action=sniff-tzsp sniff-target=IP_SURICATA sniff-target-port=37008 passthrough=yes comment="espejo a Suricata (vuelta)"
```

> **Fasttrack.** Con `fasttrack-connection` activo, mangle solo ve los primeros
> paquetes de cada conexion: se espeja el SYN y el DNS, pero no el HTTP. Excluye
> esas redes del fasttrack
> (`/ip firewall filter set [find action=fasttrack-connection] src-address=!172.16.10.0/24`)
> o usa la Opcion A.

Verificar en el servidor:

```bash
journalctl -u tzsp-decap -f          # rx/tx deben subir; ultimo_origen = IP del MikroTik
tail -f /var/log/suricata/fast.log   # y en la web EveBox
```

Como leer el log del receptor (una linea cada 60 s):

| Campo | Significado |
|---|---|
| `rx` | paquetes TZSP recibidos del MikroTik |
| `tx` | tramas Ethernet entregadas a Suricata por el veth |
| `muy_grandes` | tramas mayores que el MTU del veth; deben ser 0 con MTU 9000 |
| `ultimo_origen` | IP del MikroTik que esta espejeando |

`rx` y `tx` deben subir juntos; si `rx` sube y `tx` no, el veth esta caido o
Suricata no escucha `ids-mon`. Si `rx` no se mueve, el problema esta en el
router o en el firewall (UDP 37008).

> **Cuidado con el volumen.** TZSP duplica en la red todo lo que espejas y lo
> encapsula el CPU del router. Empieza con una red pequena o con filtros, mira el
> CPU del MikroTik (`/system resource monitor`) y `kernel_drops` en `stats.log`.
> El desencapsulador en Python aguanto ~32k pps (~100-150 Mbps) sin descartes en la
> prueba real; para varios cientos de Mbps conviene el espejo por hardware.

**Opcion C: mirror por hardware** (switch-chip, sin CPU del router). Requiere un
puerto libre en el MikroTik cableado a una NIC dedicada del servidor (en Proxmox,
un bridge propio para esa NIC, sin IP). Suricata escucha esa NIC directamente
(`-i ens19`), sin TZSP. La sintaxis depende del chip:

```routeros
# switch-chip clasico (RB, hEX, CCR con switch)
/interface ethernet switch set switch1 mirror-source=ether2 mirror-target=ether5
# CRS3xx / RB5009 (por puerto)
/interface ethernet switch port set ether2 mirror-ingress=yes mirror-egress=yes mirror-ingress-target=ether5 mirror-egress-target=ether5
```

> El envio a Loki/Grafana se agrega como modulo cuando se necesite.
