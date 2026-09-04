# suricata-ids-lab

Instalador de **Suricata en modo IDS** con **interfaz web (EveBox)** para
**Debian 13 (Trixie)** o Debian 12. Un solo comando en cualquier VPS o VM y en
minutos tienes alertas, flujos, DNS, TLS y HTTP visibles en el navegador.

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
| `-n CIDR` | `HOME_NET` | red de la interfaz |
| `-p PUERTO` | puerto de la web | `5636` |
| `-P CLAVE` | clave del usuario web `admin` | aleatoria (se muestra al final) |
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
# cambiar la clave de admin
evebox --data-directory /var/lib/evebox --config-directory /var/lib/evebox config users passwd admin

# estado / logs
systemctl status evebox
journalctl -u evebox -f
```

Config: `/etc/evebox/evebox.yaml` (backup con fecha en cada ejecucion).

Probado end-to-end el 2026-09-03 en una VM Debian 13 (virtio, Proxmox): web con
login, ingestion 1:1 con `eve.json` y alertas visibles.

## Montaje del lab

1. En Proxmox `10.0.0.2` crea una VM **Debian 13** (2 vCPU / 4–8 GB RAM basta para
   el lab; ver tabla de RAM abajo). Conectala a una `vmbr` aislada.
2. Copia este repo a la VM (a `/root/`, segun convencion) y ejecuta:

   ```bash
   chmod +x install-suricata.sh test-alerts.sh
   sudo ./install-suricata.sh
   ```

   Auto-detecta la interfaz por la ruta default y fija `HOME_NET` a su red.
   Para forzar valores:

   ```bash
   sudo ./install-suricata.sh -i ens18 -n 10.0.0.0/24
   ```

3. Confirma que detecta:

   ```bash
   sudo ./test-alerts.sh            # DNS .top + User-Agent Wget/3.0 + nmap al gateway
   tail -f /var/log/suricata/fast.log
   ```

   Las firmas de prueba son `ET DNS Query to a *.top domain` y `ET ADWARE_PUP Fake
   Wget User-Agent`; ambas vienen en ET Open. (El clasico testmynids.org ya no
   resuelve.) El trafico debe **salir por la interfaz** escuchada: lo que va por
   `lo` nunca lo ve el IDS.

## Que instala

- `suricata` + `suricata-update` (reglas **ET Open**) desde repos de Debian 13.
- **EveBox** (web) leyendo `eve.json` a SQLite, con auth y TLS. Ver seccion arriba.
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

## De lab a produccion (MikroTik real)

En el lab de 1 VM el trafico se genera localmente. Para analizar trafico real de
la red MikroTik hay que **espejarlo** hacia la interfaz que Suricata escucha:

- **TZSP (software)** — en RouterOS:
  ```
  /tool sniffer
  set filter-stream=yes streaming-enabled=yes streaming-server=<IP_SURICATA> \
      filter-interface=<wan-o-bridge>
  /tool sniffer start
  ```
  El TZSP (UDP/37008) hay que **desencapsularlo** antes de darselo a Suricata
  (p. ej. con `tzsp2pcap` hacia una interfaz dummy). Pendiente como modulo aparte
  si se decide este camino.
- **Mirror por hardware** — en MikroTik con switch-chip (`/interface ethernet
  switch mirror`), copia un puerto fisico hacia el NIC de Suricata. Cero carga de
  CPU en el router; requiere puerto y cable dedicados.

> Este repo cubre **IDS pasivo + web local**. El envio a Loki/Grafana y el
> receptor TZSP se agregan como modulos cuando se necesiten.
