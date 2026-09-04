# suricata-ids-lab

Laboratorio local de **Suricata en modo IDS** sobre **Debian 13 (Trixie)** para
pruebas en Proxmox server1 (`10.0.0.2`), aislado de produccion.

Objetivo: aprender a detectar **clientes/CPEs infectados que escanean o atacan
hacia afuera** (el caso real que motiva esto), antes de llevarlo a un MikroTik
de produccion. Alertas en logs locales (`fast.log` / `eve.json`), sin Elastic ni
dependencias externas.

## ⚡ Quick install (one-liner)

En una VM Debian 13/12 limpia, como root:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash
```

Auto-detecta la interfaz por la ruta default y fija `HOME_NET` a su red. Para
forzar interfaz y red:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/install-suricata.sh | sudo bash -s -- -i ens18 -n 10.0.0.0/24
```

Script de prueba de deteccion (se guarda en `/root`, segun convencion):

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/suricata-ids-lab/main/test-alerts.sh -o /root/test-alerts.sh && chmod +x /root/test-alerts.sh && sudo /root/test-alerts.sh
```

> La imagen `genericcloud` de Debian no trae `curl`: antes `apt-get update && apt-get install -y curl`.

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
   sudo ./test-alerts.sh            # dispara firma ET + escaneo nmap + DNS test
   tail -f /var/log/suricata/fast.log
   ```

## Que instala

- `suricata` + `suricata-update` (reglas **ET Open**) desde repos de Debian 13.
- Modo **IDS pasivo AF_PACKET** sobre la interfaz elegida.
- `HOME_NET` = red de la interfaz (para que marque bien lo "saliente").
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

> Este repo cubre el **lab local (IDS pasivo, logs locales)**. El envio a
> Loki/Grafana y el receptor TZSP se agregan como modulos cuando se necesiten.
