# 🛡️ GuardianTUI: IPS L7 de Alto Rendimiento y Dashboard de Seguridad en Tiempo Real

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/Licencia-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** es un Sistema de Prevención de Intrusiones (IPS) de grado profesional, diseñado como un **Proxy Inverso L7** de alto rendimiento. Protege tus aplicaciones web contra ataques sofisticados y técnicas de evasión mediante un **Motor de Normalización Recursiva** y un sistema de **Bloqueo Activo** en tiempo real.

---

## 🚀 Capacidades Destacadas

- **🛡️ Bloqueo Activo (Active IPS)**: Intercepta y bloquea ataques instantáneamente, sirviendo una página de bloqueo HTML con un **Incident ID** único para auditoría.
- **🔄 Motor de Normalización Recursiva**: Descapa hasta 3 niveles de codificación para detectar ataques ocultos en **Base64, URL Encoding (Doble), HTML Entities y Hex**.
- **🔍 Escaneo Exhaustivo 360°**: Analiza meticulosamente cada rincón de la petición:
    - **Headers**: Tanto nombres de cabecera como sus valores.
    - **Cookies**: Desglose y validación de cada par clave-valor.
    - **URL**: Ruta decodificada y Query Strings (parámetros `?id=...`).
    - **Body**: Inspección profunda del cuerpo del mensaje hasta 1MB.
- **📊 Dashboard TUI Avanzado**: Interfaz de terminal con búsqueda y filtrado en tiempo real por ID, IP o tipo de ataque.
- **⚡ Arquitectura Sharded**: Motor thread-safe con 64 shards para una latencia ultra baja sin contención de bloqueos.
- **🛡️ Soporte de Whitelist**: Exclusión de IPs individuales y rangos **CIDR** (ej. `10.0.0.0/8`) para tráfico de confianza.

---

## ✨ Inteligencia de Detección

### 1. OWASP Top 10 y Ataques Modernos
- **SQL Injection (SQLi)**: Detección avanzada incluyendo bypasses como `' OR TRUE--` y `admin' #`.
- **Cross-Site Scripting (XSS)**: Bloqueo de etiquetas, eventos JS y payloads modernos como `<svg/onload=`.
- **RCE / Command Injection**: Detecta ejecución de comandos con evasiones como `${IFS}` y pipes.
- **SSTI (Server-Side Template Injection)**: Protección para Jinja2, Twig, Mako (`{{7*7}}`, `${...}`).
- **NoSQL Injection**: Bloqueo de operadores de MongoDB maliciosos (`$gt`, `$regex`, `$where`).
- **Path Traversal / LFI**: Evita el acceso a `/etc/passwd`, `.env` y archivos sensibles.

### 2. Detección de Comportamiento (Anti-Bot)
- **Vulnerability Probing (Diverse)**: Identifica IPs que prueban múltiples tipos de vulnerabilidades en corto tiempo.
- **Probing Spam**: Detecta ráfagas de ataques automatizados incluso si son variados.
- **Scanner Detection**: Bloquea por firma a herramientas como `sqlmap`, `nmap`, `nuclei`, `burp`, etc.

---

## 🛠️ Inicio Rápido

### Compilar e Iniciar
```bash
go build -o guardiantui main.go
./guardiantui -listen :8080 -target https://tu-sitio-web.com
```

### Probar la Protección
```bash
# Prueba de SQLi (Codificado)
curl -G --data-urlencode "id=' OR 1=1" http://localhost:8080/

# Prueba de Evasión Base64 (Payload: ' or '1'='1)
curl http://localhost:8080/ -H "X-Attack: J29yIDEnPScx"
```

---

## ⌨️ Atajos de Teclado (TUI)

| Tecla | Acción |
| :--- | :--- |
| `q` / `Ctrl+C` | Salir de GuardianTUI |
| `/` | **Modo Búsqueda**: Filtra logs por ID, IP, Ruta o Ataque |
| `Esc` | Limpiar filtro o cancelar búsqueda |
| `↑` / `↓` | Desplazarse por el historial de peticiones |

---

## 📝 Registro Forense

Logs detallados en `guardian.log` con contexto de detección:
```log
[2026-03-29 23:51:43] ID:b6e91bc4 IP:[::1]:47820 GET / | Status:BLOCKED | Agent:curl/8.5.0
  ↳ [DETECTION] Type:Bot: Malicious Scanner | Pattern:curl
```

---

## 📜 Licencia
Distribuido bajo la **Licencia MIT**.
