# Atribución — assets del mapa mundial

Estos archivos se usan para dibujar el mapa "A dónde atacan tus CPEs" (coropleta por país).

- **`countries-110m.json`** — World Atlas TopoJSON (resolución 1:110m).
  Fuente: https://github.com/topojson/world-atlas (derivado de Natural Earth,
  **dominio público**). ISC License.

- **`topojson-client.min.js`** — TopoJSON Client (expande TopoJSON a GeoJSON).
  Fuente: https://github.com/topojson/topojson-client — © Mike Bostock, **ISC License**.

La lógica de coropleta por país (proyección equirectangular, tabla id→ISO2 y el
render) se inspiró en **MikroDash** (https://github.com/mtandazo35/MikroDash),
**MIT License**, © 2026 MikroDash. Reimplementada aquí en el estilo del panel.

La geolocalización IP→país NO usa `geoip-lite` (Node/GeoLite2): se resuelve del lado del
servidor en Python con la base **DB-IP lite** (IP→país), distribuida por
https://github.com/sapics/ip-location-db (`dbip-country/dbip-country-ipv4.csv`).
Licencia **CC-BY-4.0**, © [db-ip.com](https://db-ip.com). El instalador la descarga y la
convierte a un binario compacto en `/var/lib/suricata-geoip/ipv4.bin`.
