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

La geolocalización IP→país NO usa `geoip-lite` (Node/GeoLite2): se resuelve con una
base IP→país de dominio público (ip-location-db, CC0) del lado del servidor en Python.
