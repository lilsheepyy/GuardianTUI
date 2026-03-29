# 🛡️ GuardianTUI: IPS L7 de Alto Rendimiento y Dashboard de Seguridad en Tiempo Real

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** es un Sistema de Prevención de Intrusiones (IPS) de grado carrier, de código abierto y **Proxy Inverso L7** diseñado para ofrecer velocidad extrema, seguridad y visibilidad total. Impulsado por un **Motor Sharded Thread-Safe** en Go, protege tus aplicaciones contra amenazas modernas mientras proporciona una interfaz de terminal (**TUI**) espectacular en tiempo real.

---

## 🚀 ¿Por qué GuardianTUI?

- **🛡️ Firewall L7 Activo**: Inspección Profunda de Paquetes (DPI) para bloquear SQLi, XSS, RCE y más.
- **🍪 Inspección de Cookies**: Escanea cada valor de cookie en busca de cargas maliciosas ocultas.
- **📊 Dashboard TUI en Vivo**: Monitoriza cada petición y amenaza según ocurre, directamente en tu terminal.
- **⚡ Arquitectura Sharded**: Utiliza 64 shards concurrentes para eliminar la contención de bloqueos (lock contention), garantizando una latencia ultra baja bajo carga pesada.
- **🔍 Logs Forenses**: Informes de incidentes detallados con IDs únicos, cabeceras completas y muestras de payload.

---

## ✨ Capacidades de Detección Avanzada

GuardianTUI identifica y mitiga una amplia gama de amenazas:

### 1. OWASP Top 10 y Ataques de Carga (Payload)
- **Inyección SQL (SQLi)**: Detecta inyecciones clásicas, ciegas (blind) y basadas en evasión.
- **Cross-Site Scripting (XSS)**: Identifica etiquetas de script, gestores de eventos y protocolos falsos `javascript:`.
- **Ejecución Remota de Código (RCE)**: Bloquea inyecciones de comandos (`system`, `exec`, `shell_exec`, etc.).
- **Path Traversal / LFI / RFI**: Evita el acceso a archivos sensibles del sistema como `/etc/passwd`.

### 2. Huella de Bots y Escáneres (40+ Firmas)
- **Escáneres de Seguridad**: Acunetix, Nessus, Qualys, Netsparker, OpenVAS, Arachni.
- **Herramientas de Pentest**: nmap, sqlmap, nuclei, nikto, ffuf, gobuster, dirsearch, feroxbuster.
- **Bots Agresivos**: Shodan, Censys, MJ12bot, AhrefsBot, SemrushBot.
- **Cabeceras Técnicas**: Detecta herramientas mediante cabeceras específicas como `X-Scanner`, `X-Bug-Bounty` y `X-Scan-ID`.

### 3. Protección de Estado (Stateful)
- **Anti-DoS / Fuerza Bruta**: Rastrea tasas de peticiones por IP usando un rastreador sharded de alto rendimiento.
- **Escudo de Datos Sensibles**: Bloquea intentos de acceder a `.env`, `.git`, credenciales de AWS y archivos de configuración de WordPress.

---

## 🛠️ Instalación y Inicio Rápido

### Compilar desde el código fuente
```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

### Protege tu API / Web
```bash
./guardiantui -listen :9090 -target http://localhost:8080
```

---

## 📝 Registro Forense (Listo para Sysadmins)

Informes detallados en `guardian.log`, ideales para auditorías o integración con Fail2Ban:
```log
[2026-03-29 16:45:10] ID:a1b2c3d4 IP:1.2.3.4 POST /api/v1/upload | Status:ALERT:Command Injection | Agent:curl/8.1.2
  ↳ [DETECTION] Type:Command Injection | Pattern:(?i)(exec|system|shell_exec|eval)
  ↳ [PAYLOAD] {"file": "test.txt", "cmd": "rm -rf /; id"}
```

---

## ⌨️ Atajos de Teclado (TUI)

| Tecla | Acción |
| :--- | :--- |
| `q` / `Ctrl+C` | Salir de GuardianTUI |
| `b` | **Bloquear** la dirección IP seleccionada instantáneamente |
| `↑` / `↓` | Desplazarse por el historial de peticiones |

---

## 🏷️ Etiquetas y SEO
#Ciberseguridad #Golang #IDS #IPS #Networking #OpenSource #DevSecOps #InfoSec #L7Firewall #TUI #ProxyInverso #OWASP #DeteccionDeAmenazas #SeguridadInformatica #AntiBot #WAF

---

## 📜 Licencia
Distribuido bajo la **Licencia MIT**.
