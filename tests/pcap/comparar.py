#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compara lo que Suricata saco de una captura con lo que ese caso debe dar.

Salida por stdout en una linea y codigo de salida:
    0   el caso cumple
    1   FALLA   (caso obligatorio incumplido: rompe la suite)
    1   AVISO   (caso informativo incumplido: no rompe, pero se avisa)

La diferencia importa. Un benigno que alerta es un fallo nuestro y hay que arreglarlo.
Un ataque que no se detecta puede ser que ET Open haya retirado la firma esta semana, y
eso no es motivo para dejar el repositorio en rojo: es motivo para mirarlo.
"""
import json
import sys


def alertas_de(ruta):
    """Las firmas del eve.json, o None si no se pudo leer.

    La diferencia importa: si Suricata no llego a arrancar no hay eve.json, y tratar eso
    como "ninguna alerta" haria que todos los casos benignos pasaran en verde sin haber
    analizado nada. Un banco de regresion que aprueba cuando no se ejecuto es peor que
    no tenerlo, porque da confianza falsa."""
    out = []
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            for linea in f:
                try:
                    d = json.loads(linea)
                except ValueError:
                    continue
                if d.get("event_type") == "alert":
                    out.append((d.get("alert") or {}).get("signature", ""))
    except OSError:
        return None
    return out


def main():
    if len(sys.argv) < 3:
        print("uso: comparar.py expected.json eve.json")
        return 1
    try:
        esp = json.load(open(sys.argv[1], encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("no se pudo leer lo esperado: %s" % e)
        return 1

    firmas = alertas_de(sys.argv[2])
    if firmas is None:
        print("FALLA no hay eve.json: Suricata no llego a analizar la captura (%s)"
              % sys.argv[2])
        return 1
    n = len(firmas)
    obligatorio = bool(esp.get("obligatorio", True))
    pre = "FALLA" if obligatorio else "AVISO"
    problemas = []

    if "max_alertas" in esp and n > int(esp["max_alertas"]):
        # las tres primeras firmas bastan para saber que regla hay que excluir
        muestra = ", ".join(sorted(set(firmas))[:3])
        problemas.append("%d alerta(s) donde se esperaban como mucho %d: %s"
                         % (n, int(esp["max_alertas"]), muestra))

    if "min_alertas" in esp and n < int(esp["min_alertas"]):
        problemas.append("%d alerta(s), se esperaba al menos %d"
                         % (n, int(esp["min_alertas"])))

    bajas = " | ".join(firmas).lower()
    faltan = [t for t in (esp.get("must_alert") or []) if t.lower() in bajas]
    if esp.get("must_alert") and not faltan:
        # basta con que UNA de las palabras aparezca: las firmas de ET cambian de
        # nombre a menudo y exigir una exacta convierte el banco en un estorbo
        problemas.append("ninguna alerta menciona %s"
                         % " ni ".join(esp["must_alert"]))

    for t in (esp.get("must_not_alert") or []):
        if t.lower() in bajas:
            problemas.append("alerto por '%s', que en este caso no corresponde" % t)

    if problemas:
        print("%s %s" % (pre, "; ".join(problemas)))
        return 1
    print("%d alerta(s)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
