#!/usr/bin/env python3
"""
email_forense.py — Analizador de phishing en correos electrónicos (.eml)

Analiza un correo electrónico exportado en formato .eml en busca de
indicios de phishing: fallos de autenticación (SPF/DKIM/DMARC), discrepancias
entre remitente/Reply-To/Return-Path, enlaces sospechosos, adjuntos de riesgo
y lenguaje de urgencia — todo con la librería estándar de Python, sin
dependencias externas ni envío de datos a ningún servicio de terceros.

Cómo exportar un correo a .eml:
  - Gmail: abrir el correo > menú (⋮) > "Mostrar original" > "Descargar original"
  - Outlook: abrir el correo > Archivo > Guardar como > tipo "Correo electrónico"
  - Thunderbird: arrastrar el correo a una carpeta del escritorio

Autora: Nieves Casquero — Perito Informático de Parte (Colegiada AEPEJU)
Licencia: MIT
"""

import argparse
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

VERSION = "1.0.0"

ACORTADORES = {
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd", "goo.gl", "ow.ly",
    "shorturl.at", "rebrand.ly", "buff.ly", "tiny.cc", "s.id", "rb.gy",
}

TLDS_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "link", "work",
    "surf", "loan", "gd", "cam", "icu", "cyou",
}

PALABRAS_URGENCIA = [
    "urgente", "urgent", "verifica tu cuenta", "verify your account", "suspendida",
    "suspended", "bloqueada", "blocked", "actualiza tus datos", "action required",
    "última oportunidad", "24 horas", "48 horas", "confirma ahora", "click aquí",
    "haz clic aquí", "premio", "has ganado", "factura pendiente", "pago pendiente",
]

EXTENSIONES_PELIGROSAS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".msi", ".ps1", ".hta",
}

EXTENSIONES_MACRO = {".docm", ".xlsm", ".pptm"}


def dominio_de(direccion: str) -> str:
    if not direccion:
        return ""
    m = re.search(r"@([\w.-]+)", direccion)
    return m.group(1).lower() if m else ""


def analizar_cabeceras(msg):
    hallazgos = []
    puntuacion = 0

    remitente = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    dom_from = dominio_de(remitente)
    dom_reply = dominio_de(reply_to)
    dom_return = dominio_de(return_path)

    if dom_reply and dom_reply != dom_from:
        hallazgos.append(f"El dominio de 'Reply-To' ({dom_reply}) no coincide con el de 'From' ({dom_from}). "
                         "Las respuestas irían a un dominio distinto del que aparenta enviar el correo.")
        puntuacion += 4

    if dom_return and dom_from and dom_return != dom_from:
        hallazgos.append(f"El dominio de 'Return-Path' ({dom_return}) no coincide con el de 'From' ({dom_from}).")
        puntuacion += 2

    auth_results = msg.get("Authentication-Results", "") or ""
    for mecanismo in ["spf", "dkim", "dmarc"]:
        m = re.search(rf"{mecanismo}=(\w+)", auth_results, re.IGNORECASE)
        if m:
            resultado = m.group(1).lower()
            if resultado not in ("pass", "none"):
                hallazgos.append(f"{mecanismo.upper()} ha fallado ({resultado}) según la cabecera "
                                 "Authentication-Results — indicio fuerte de suplantación.")
                puntuacion += 5
            elif resultado == "none":
                hallazgos.append(f"{mecanismo.upper()} no está configurado para verificar este correo (resultado 'none').")
                puntuacion += 1
        else:
            hallazgos.append(f"No se ha encontrado un resultado de {mecanismo.upper()} en las cabeceras "
                             "(el correo puede no incluir Authentication-Results, o fue eliminado al reenviar).")

    received = msg.get_all("Received", [])
    num_saltos = len(received)

    return {
        "remitente": remitente,
        "reply_to": reply_to,
        "return_path": return_path,
        "dominio_from": dom_from,
        "num_saltos_received": num_saltos,
        "hallazgos": hallazgos,
        "puntuacion": puntuacion,
    }


def extraer_urls(msg):
    urls = set()
    for parte in msg.walk():
        if parte.get_content_type() in ("text/plain", "text/html"):
            try:
                contenido = parte.get_content()
            except Exception:
                continue
            for m in re.finditer(r'href=[\'"]?([^\'" >]+)|(\bhttps?://[^\s<>"\']+)', contenido, re.IGNORECASE):
                url = m.group(1) or m.group(2)
                if url and url.lower().startswith(("http://", "https://")):
                    urls.add(url.rstrip(").,;"))
    return list(urls)


def analizar_url(url: str):
    hallazgos = []
    puntuacion = 0
    partes = urllib.parse.urlsplit(url)
    host = (partes.hostname or "").lower()

    if "@" in partes.netloc:
        hallazgos.append(f"'{url}' contiene '@' — técnica clásica para ocultar el dominio real.")
        puntuacion += 4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        hallazgos.append(f"'{url}' apunta a una IP en lugar de un dominio.")
        puntuacion += 3
    if host.startswith("xn--") or ".xn--" in host:
        hallazgos.append(f"'{url}' usa codificación Punycode — posible ataque homógrafo.")
        puntuacion += 3
    if host in ACORTADORES:
        hallazgos.append(f"'{url}' usa un acortador de enlaces ({host}), oculta el destino real.")
        puntuacion += 2
    tld = host.split(".")[-1] if "." in host else ""
    if tld in TLDS_SOSPECHOSOS:
        hallazgos.append(f"'{url}' usa un TLD (.{tld}) frecuente en campañas de phishing.")
        puntuacion += 1

    return hallazgos, puntuacion


def analizar_adjuntos(msg):
    hallazgos = []
    puntuacion = 0
    for parte in msg.iter_attachments():
        nombre = parte.get_filename() or ""
        if not nombre:
            continue
        ext = Path(nombre).suffix.lower()
        num_puntos = nombre.count(".")
        if ext in EXTENSIONES_PELIGROSAS:
            hallazgos.append(f"Adjunto '{nombre}': extensión ejecutable ({ext}) — alto riesgo.")
            puntuacion += 5
        elif ext in EXTENSIONES_MACRO:
            hallazgos.append(f"Adjunto '{nombre}': documento Office con macros habilitadas ({ext}).")
            puntuacion += 3
        if num_puntos >= 2:
            hallazgos.append(f"Adjunto '{nombre}': doble extensión — técnica para disfrazar un ejecutable "
                             "como si fuera un documento (ej. 'factura.pdf.exe').")
            puntuacion += 4
    return hallazgos, puntuacion


def analizar_urgencia(msg):
    asunto = (msg.get("Subject", "") or "").lower()
    cuerpo = ""
    for parte in msg.walk():
        if parte.get_content_type() == "text/plain":
            try:
                cuerpo += parte.get_content().lower()
            except Exception:
                pass

    texto = asunto + " " + cuerpo
    encontradas = [p for p in PALABRAS_URGENCIA if p in texto]
    return encontradas


def clasificar_riesgo(puntuacion: int) -> str:
    if puntuacion >= 10:
        return "ALTO"
    if puntuacion >= 5:
        return "MEDIO"
    return "BAJO"


def construir_informe(path, cab, urls_analizadas, adjuntos_hallazgos, urgencia, puntuacion_total):
    lines = []
    lines.append("# Informe de Análisis de Phishing en Correo Electrónico\n")
    lines.append(f"**Archivo analizado:** `{path.name}`  ")
    lines.append(f"**Fecha de análisis (UTC):** {datetime.now(timezone.utc).isoformat()}  ")
    lines.append(f"**Remitente (From):** {cab['remitente']}  ")
    if cab['reply_to']:
        lines.append(f"**Reply-To:** {cab['reply_to']}  ")
    lines.append(f"**Saltos de servidor (Received):** {cab['num_saltos_received']}\n")

    riesgo = clasificar_riesgo(puntuacion_total)
    emoji = {"ALTO": "🔴", "MEDIO": "🟠", "BAJO": "🟢"}[riesgo]
    lines.append(f"## {emoji} Nivel de riesgo: {riesgo} (puntuación {puntuacion_total})\n")

    lines.append("## Cabeceras y autenticación\n")
    for h in cab["hallazgos"]:
        lines.append(f"- {h}")

    lines.append("\n## Enlaces encontrados\n")
    if not urls_analizadas:
        lines.append("No se han encontrado enlaces en el cuerpo del mensaje.")
    else:
        for url, (hallazgos, _) in urls_analizadas.items():
            if hallazgos:
                lines.append(f"🔴 `{url}`")
                for h in hallazgos:
                    lines.append(f"  - {h}")
            else:
                lines.append(f"🟢 `{url}` — sin patrones sospechosos estructurales")

    lines.append("\n## Adjuntos\n")
    if not adjuntos_hallazgos:
        lines.append("Sin adjuntos, o ningún adjunto con indicios de riesgo.")
    else:
        for h in adjuntos_hallazgos:
            lines.append(f"- 🔴 {h}")

    lines.append("\n## Lenguaje de presión/urgencia\n")
    if urgencia:
        lines.append(f"Se han encontrado los siguientes términos: {', '.join(set(urgencia))}.")
    else:
        lines.append("No se han detectado términos de urgencia habituales en phishing.")

    lines.append("\n## ⚖️ Recomendaciones\n")
    lines.append("- No hagas clic en los enlaces ni descargues los adjuntos de este correo si el riesgo es MEDIO o ALTO.")
    lines.append("- Verifica al remitente por un canal distinto al propio correo (teléfono, web oficial escrita a mano).")
    lines.append("- Si el correo suplanta a tu banco, empresa o una administración, repórtalo (ej. a phishing@empresa.com o vía INCIBE: incibe.es).")

    lines.append("\n## Límites de este análisis\n")
    lines.append("- Es un análisis **heurístico y estructural** de las cabeceras y el contenido, no consulta "
                 "listas negras en tiempo real ni analiza el contenido de las webs enlazadas.")
    lines.append("- La ausencia de indicios no garantiza que el correo sea legítimo; la presencia de indicios "
                 "no es una prueba definitiva de phishing por sí sola.")

    lines.append("\n---\n")
    lines.append(f"*Generado con email_forense.py v{VERSION} — "
                 "https://github.com/AnkbNikas/email-forense*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        prog="email_forense",
        description="Analiza un correo .eml en busca de indicios de phishing."
    )
    parser.add_argument("eml", help="Ruta al archivo .eml a analizar")
    parser.add_argument("--salida", default="informe_email", help="Nombre base de los ficheros de salida")
    args = parser.parse_args()

    path = Path(args.eml)
    if not path.exists():
        print(f"Error: el archivo '{args.eml}' no existe.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analizando: {path}")
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    cab = analizar_cabeceras(msg)
    urls = extraer_urls(msg)
    urls_analizadas = {}
    puntuacion_urls = 0
    for url in urls:
        hallazgos, puntos = analizar_url(url)
        urls_analizadas[url] = (hallazgos, puntos)
        puntuacion_urls += puntos

    adjuntos_hallazgos, puntuacion_adjuntos = analizar_adjuntos(msg)
    urgencia = analizar_urgencia(msg)
    puntuacion_urgencia = 1 if urgencia else 0

    puntuacion_total = cab["puntuacion"] + puntuacion_urls + puntuacion_adjuntos + puntuacion_urgencia
    riesgo = clasificar_riesgo(puntuacion_total)
    print(f"[*] Riesgo: {riesgo} (puntuación {puntuacion_total})")

    informe = construir_informe(path, cab, urls_analizadas, adjuntos_hallazgos, urgencia, puntuacion_total)

    md_path = Path(f"{args.salida}.md")
    md_path.write_text(informe, encoding="utf-8")

    json_path = Path(f"{args.salida}.json")
    json_path.write_text(json.dumps({
        "archivo": str(path),
        "cabeceras": cab,
        "urls": {u: {"hallazgos": h, "puntuacion": p} for u, (h, p) in urls_analizadas.items()},
        "adjuntos_hallazgos": adjuntos_hallazgos,
        "urgencia_detectada": urgencia,
        "puntuacion_total": puntuacion_total,
        "riesgo": riesgo,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Informe Markdown: {md_path}")
    print(f"[+] Datos JSON:       {json_path}")


if __name__ == "__main__":
    main()
