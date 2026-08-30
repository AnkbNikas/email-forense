# Informe de Análisis de Phishing en Correo Electrónico

**Archivo analizado:** `phishing_santander.eml`  
**Fecha de análisis (UTC):** 2026-08-30T11:46:03.244659+00:00  
**Remitente (From):** Banco Santander - Seguridad <soporte@santander-verificacion.top>  
**Reply-To:** soporte@atencion-clientes.xyz  
**Saltos de servidor (Received):** 2

## 🔴 Nivel de riesgo: ALTO (puntuación 36)

## Cabeceras y autenticación

- El dominio de 'Reply-To' (atencion-clientes.xyz) no coincide con el de 'From' (santander-verificacion.top). Las respuestas irían a un dominio distinto del que aparenta enviar el correo.
- El dominio de 'Return-Path' (mailrelay-service.ru) no coincide con el de 'From' (santander-verificacion.top).
- SPF ha fallado (fail) según la cabecera Authentication-Results — indicio fuerte de suplantación.
- DKIM ha fallado (fail) según la cabecera Authentication-Results — indicio fuerte de suplantación.
- DMARC ha fallado (fail) según la cabecera Authentication-Results — indicio fuerte de suplantación.

## Enlaces encontrados

🔴 `https://bit.ly/3xSantander`
  - 'https://bit.ly/3xSantander' usa un acortador de enlaces (bit.ly), oculta el destino real.
🔴 `https://185.23.44.109/login/verify`
  - 'https://185.23.44.109/login/verify' apunta a una IP en lugar de un dominio.

## Adjuntos

- 🔴 Adjunto 'factura.pdf.exe': extensión ejecutable (.exe) — alto riesgo.
- 🔴 Adjunto 'factura.pdf.exe': doble extensión — técnica para disfrazar un ejecutable como si fuera un documento (ej. 'factura.pdf.exe').

## Lenguaje de presión/urgencia

Se han encontrado los siguientes términos: bloqueada, 24 horas, urgent, urgente.

## ⚖️ Recomendaciones

- No hagas clic en los enlaces ni descargues los adjuntos de este correo si el riesgo es MEDIO o ALTO.
- Verifica al remitente por un canal distinto al propio correo (teléfono, web oficial escrita a mano).
- Si el correo suplanta a tu banco, empresa o una administración, repórtalo (ej. a phishing@empresa.com o vía INCIBE: incibe.es).

## Límites de este análisis

- Es un análisis **heurístico y estructural** de las cabeceras y el contenido, no consulta listas negras en tiempo real ni analiza el contenido de las webs enlazadas.
- La ausencia de indicios no garantiza que el correo sea legítimo; la presencia de indicios no es una prueba definitiva de phishing por sí sola.

---

*Generado con email_forense.py v1.0.0 — https://github.com/AnkbNikas/email-forense*