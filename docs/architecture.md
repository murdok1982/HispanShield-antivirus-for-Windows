# HispanShield — Arquitectura del Sistema

## Visión general

HispanShield es un antivirus open-source para Windows 10/11 compuesto por dos binarios principales:

| Componente | Binario | Descripción |
|---|---|---|
| Agente | `hispanshield-agent.exe` | Windows Service en Rust. Detección, monitoreo y protección. |
| Dashboard | `hispanshield-ui.exe` | Interfaz Tauri + React. Visualización y control. |

Comunicación: Named Pipe `\\.\pipe\HispanShieldAgent` con JSON-RPC 2.0 autenticado por HMAC-SHA256.

---

## Diagrama de arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                     WINDOWS 10 / 11                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │    hispanshield-agent.exe  (Windows Service / SYSTEM)     │  │
│  │                                                           │  │
│  │  MONITORES (tokio async tasks)                            │  │
│  │  ┌────────────┐ ┌──────────────┐ ┌────────────────────┐  │  │
│  │  │FileMonitor │ │ProcessMonitor│ │  NetworkMonitor    │  │  │
│  │  │(notify +   │ │(Toolhelp32 + │ │ (GetExtendedTcp/   │  │  │
│  │  │ ReadDirChg)│ │ ETW/WMI)     │ │  UdpTable)         │  │  │
│  │  └─────┬──────┘ └──────┬───────┘ └─────────┬──────────┘  │  │
│  │        │               │                   │              │  │
│  │  ┌─────▼───────────────▼───────────────────▼──────────┐  │  │
│  │  │                 Detection Engine                    │  │  │
│  │  │  ┌───────────┐  ┌──────────┐  ┌─────────────────┐  │  │  │
│  │  │  │ HashDetect│  │  YARA    │  │  Heuristics +   │  │  │  │
│  │  │  │(SHA256/   │  │ Detector │  │  Behavior       │  │  │  │
│  │  │  │ SHA1/MD5) │  │          │  │  Analysis       │  │  │  │
│  │  │  └───────────┘  └──────────┘  └─────────────────┘  │  │  │
│  │  │  ┌─────────────────────────────────────────────┐    │  │  │
│  │  │  │         Scoring Engine (0 – 100)            │    │  │  │
│  │  │  └─────────────────────────────────────────────┘    │  │  │
│  │  └───────────────────────────┬─────────────────────────┘  │  │
│  │                              │                             │  │
│  │  ┌───────────────────────────▼─────────────────────────┐  │  │
│  │  │                   Action Engine                      │  │  │
│  │  │   AlertOnly │ Quarantine │ KillProcess │ BlockFW     │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │                                                           │  │
│  │  ┌──────────────┐  ┌────────────────┐  ┌─────────────┐  │  │
│  │  │ ThreatIntel  │  │   SQLite DB    │  │  Quarantine │  │  │
│  │  │ FeedManager  │  │ events|threats │  │  Manager    │  │  │
│  │  │ (OSINT feeds │  │ quarantine     │  │ (UUID+DACL) │  │  │
│  │  │ + IOC cache) │  │ ioc_cache      │  └─────────────┘  │  │
│  │  └──────────────┘  │ feed_status    │                    │  │
│  │                    └────────────────┘                    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  IPC Server — Named Pipe JSON-RPC 2.0               │  │  │
│  │  │  \\.\pipe\HispanShieldAgent                         │  │  │
│  │  │  Autenticación: token HMAC-SHA256                   │  │  │
│  │  └──────────────────────┬──────────────────────────────┘  │  │
│  └─────────────────────────┼─────────────────────────────────┘  │
│                             │ Named Pipe                         │
│  ┌──────────────────────────▼────────────────────────────────┐  │
│  │  hispanshield-ui.exe  (Tauri 2 + React + Tailwind CSS)    │  │
│  │                                                           │  │
│  │  Tauri Rust Backend                                       │  │
│  │  └── IpcClient → Named Pipe → IpcServer                  │  │
│  │                                                           │  │
│  │  React Frontend (TypeScript + Zustand)                    │  │
│  │  ┌──────────┐ ┌─────────┐ ┌────────┐ ┌────────────────┐  │  │
│  │  │Dashboard │ │Threats  │ │  Scan  │ │  Quarantine    │  │  │
│  │  └──────────┘ └─────────┘ └────────┘ └────────────────┘  │  │
│  │  ┌──────────┐ ┌─────────┐ ┌────────┐ ┌────────────────┐  │  │
│  │  │Processes │ │Conns.   │ │  Intel │ │  Logs/Settings │  │  │
│  │  └──────────┘ └─────────┘ └────────┘ └────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Protocolo IPC

```
Pipe:      \\.\pipe\HispanShieldAgent
Protocolo: JSON-RPC 2.0 sobre Named Pipe (line-delimited, \n al final)
Auth:      Campo "auth" en cada request con token almacenado en
           %ProgramData%\HispanShield\ipc_token

Request:
{
  "jsonrpc": "2.0",
  "method": "get_threats",
  "params": { "limit": 100, "offset": 0 },
  "id": 1,
  "auth": "<token>"
}

Response OK:
{ "jsonrpc": "2.0", "result": [...], "id": 1 }

Response Error:
{ "jsonrpc": "2.0", "error": { "code": -32001, "message": "Unauthorized" }, "id": 1 }
```

### Métodos disponibles

| Método | Descripción |
|---|---|
| `get_status` | Estado del agente (running, protection, version, uptime) |
| `get_stats` | Estadísticas (threats, quarantine, ioc_count, events_today) |
| `get_threats` | Lista de amenazas detectadas |
| `get_events` | Log de eventos |
| `get_quarantine` | Archivos en cuarentena |
| `get_processes` | Snapshot de procesos activos |
| `get_connections` | Conexiones de red activas |
| `get_feed_status` | Estado de cada feed OSINT |
| `get_config` | Configuración actual |
| `set_config` | Actualizar configuración |
| `scan_file` | Escanear un archivo específico |
| `scan_path` | Escanear una ruta recursivamente |
| `quarantine_file` | Mover archivo a cuarentena |
| `restore_quarantine` | Restaurar archivo de cuarentena |
| `delete_quarantine` | Eliminar archivo de cuarentena |
| `kill_process` | Terminar un proceso por PID |
| `update_feeds` | Actualizar todos los feeds OSINT |
| `pause_protection` | Pausar protección en tiempo real |
| `resume_protection` | Reanudar protección |
| `add_exception` | Añadir ruta a la lista blanca |
| `block_ioc` | Añadir IOC a la lista de bloqueo manual |

---

## Modelo de datos SQLite

### `events`
Log de todos los eventos del agente.

| Campo | Tipo | Descripción |
|---|---|---|
| id | INTEGER PK | Autoincrement |
| timestamp | TEXT | ISO 8601 UTC |
| event_type | TEXT | FileScan, ProcessStart, NetworkConn, RegistryChange, Threat, Quarantine, FeedUpdate |
| severity | TEXT | Info, Low, Medium, High, Critical |
| source | TEXT | Módulo origen (FileMonitor, ProcessMonitor, etc.) |
| path | TEXT | Ruta del archivo o registro |
| pid | INTEGER | PID del proceso |
| process_name | TEXT | Nombre del proceso |
| score | INTEGER | Score de riesgo 0-100 |
| details | TEXT | JSON con detalles adicionales |
| resolved | INTEGER | 0/1 |

### `threats`
Amenazas detectadas con estado de resolución.

### `quarantine`
Archivos en cuarentena con metadata completa (UUID, ruta original, hashes, tamaño).

### `ioc_cache`
IOCs normalizados de todos los feeds. Índice por (ioc_type, value).

Tipos: `ip`, `domain`, `url`, `sha256`, `sha1`, `md5`, `yara_rule`

### `feed_status`
Estado de actualización de cada feed (last_updated, next_update, ioc_count, status).

### `process_snapshot`
Snapshot periódico de procesos activos con scoring y flags de detección.

### `network_connections`
Conexiones TCP/UDP activas mapeadas a PID y proceso.

### `config_store`
Configuración clave-valor persistente.

---

## Flujo de detección

```
Evento (archivo/proceso/red)
        │
        ▼
   ¿En allowlist/excepción? → SÍ → Ignorar
        │ NO
        ▼
   HashDetector → consulta IOC cache (SHA256, SHA1, MD5)
        │
        ▼
   YaraDetector → escanea con reglas compiladas
        │
        ▼
   HeuristicDetector → rutas sospechosas, LOLBins, doble extensión, etc.
        │
        ▼
   NetworkDetector → IOC match en IPs/dominios, beaconing
        │
        ▼
   ScoringEngine → suma factores → score 0-100
        │
        ▼
   ¿score >= threshold? → SÍ → Action Engine
        │ NO
        ▼
        Log (Info)

Action Engine:
  - AlertOnly   → insert threat + event (severity=High/Critical)
  - Quarantine  → QuarantineManager.quarantine_file() + insert threat
  - Block       → FirewallManager.block_program() + insert threat
  - KillAndQuar → kill_process() + quarantine_file() + insert threat
```

---

## Decisiones técnicas

| Decisión | Alternativa | Razón |
|---|---|---|
| Rust para el agente | C++ / C# | Seguridad de memoria, rendimiento, binario pequeño |
| Tauri 2 para UI | Electron | 10× más ligero, Rust nativo, sin V8 overhead |
| Named Pipe para IPC | HTTP/localhost | Nativo Windows, autenticable con ACLs |
| SQLite embebido | PostgreSQL | Sin servidor, cero dependencias, funciona offline |
| YARA | Regex puro | Estándar de industria, miles de reglas disponibles |
| `notify` crate | DeviceIoControl | Más simple, cross-platform ready |
| Sin driver kernel | minifilter | Requiere EV signing ($400+/año), riesgo de BSOD |

---

## Limitaciones (sin driver kernel)

1. Detección **post-ejecución** — no puede bloquear antes de que el proceso arranque
2. No puede proteger su propio proceso de terminación forzada por un proceso privilegiado
3. No intercepta syscalls directas (solo monitorea eventos del sistema)
4. Malware con anti-análisis avanzado puede detectar el monitoreo
5. Sin kernel mode, no puede hacer HTTPS inspection (no MITM)
6. Algunos ETW providers del kernel requieren permisos adicionales
