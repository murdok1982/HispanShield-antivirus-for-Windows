# Inteligencia de Amenazas — Feeds OSINT

HispanShield descarga y cachea localmente IOCs de fuentes públicas y gratuitas. No requiere API keys. Funciona offline usando la última copia descargada.

## Feeds incluidos por defecto

### MalwareBazaar (abuse.ch)
- **URL**: `https://bazaar.abuse.ch/export/csv/full/`
- **Formato**: CSV
- **IOC types**: SHA-256, SHA-1, MD5
- **TTL recomendado**: 24h
- **Descripción**: Base de datos de muestras de malware. Cada fila incluye el hash, nombre del malware, familia, origen y fecha de subida.
- **Campos relevantes**: `sha256_hash`, `sha1_hash`, `md5_hash`, `file_name`, `signature`, `tags`

### ThreatFox (abuse.ch)
- **URL**: `https://threatfox.abuse.ch/export/csv/full/`
- **Formato**: CSV
- **IOC types**: IP, domain, URL, SHA-256, MD5
- **TTL**: 12h
- **Descripción**: IOCs de familias de malware activas con nivel de confianza. Incluye IPs y dominios de C2.
- **Campos relevantes**: `ioc_value`, `ioc_type`, `threat_type`, `malware`, `confidence_level`, `tags`

### URLhaus (abuse.ch)
- **URL**: `https://urlhaus.abuse.ch/downloads/csv/`
- **Formato**: CSV
- **IOC types**: URL, domain
- **TTL**: 6h
- **Descripción**: URLs utilizadas para distribuir malware. Alta frecuencia de actualización.
- **Campos relevantes**: `url`, `url_status`, `tags`, `url_haus_link`

### Feodo Tracker — IPs (abuse.ch)
- **URL**: `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`
- **Formato**: TXT (una IP por línea, comentarios con #)
- **IOC types**: IPv4
- **TTL**: 6h
- **Descripción**: IPs de servidores C2 de botnets conocidas (Emotet, Dridex, TrickBot, QakBot, BazarLoader).

### Feodo Tracker — Dominios (abuse.ch)
- **URL**: `https://feodotracker.abuse.ch/downloads/domainblocklist.txt`
- **Formato**: TXT
- **IOC types**: domain
- **TTL**: 6h

### SSL Blacklist (abuse.ch)
- **URL**: `https://sslbl.abuse.ch/blacklist/sslipbl.csv`
- **Formato**: CSV
- **IOC types**: IP
- **TTL**: 12h
- **Descripción**: IPs asociadas a certificados SSL maliciosos o C2 encriptados.

### MISP Warninglists — Alexa Top
- **URL**: `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/alexa/list.json`
- **Formato**: JSON
- **IOC types**: domain (allowlist)
- **TTL**: 168h (1 semana)
- **Propósito**: Reducir falsos positivos en dominios populares legítimos.

### MISP Warninglists — Microsoft
- **URL**: `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/microsoft/list.json`
- **Formato**: JSON
- **IOC types**: domain, IP (allowlist)
- **TTL**: 168h
- **Propósito**: IPs y dominios de Microsoft — evitar bloquear servicios de Windows Update.

---

## Modelo de IOC normalizado

Todos los feeds se normalizan al siguiente esquema antes de guardarse en SQLite:

```
{
  ioc_type:   "ip" | "domain" | "url" | "sha256" | "sha1" | "md5" | "yara_rule"
  value:      string  (el valor del IOC)
  source:     string  (nombre del feed)
  confidence: integer (0-100)
  first_seen: ISO 8601
  last_seen:  ISO 8601
  tags:       JSON array de strings
  is_allowlist: boolean
}
```

---

## Proceso de actualización

1. El `FeedManager` comprueba el TTL de cada feed en `feed_status`
2. Si `now > next_update`, descarga el feed vía HTTPS
3. Parsea el formato específico de cada feed
4. Normaliza a `IocEntry` y hace `UPSERT` en SQLite (no duplica, actualiza si ya existe)
5. Actualiza `feed_status` con timestamp, count y checksum
6. En modo offline: si falla la descarga, usa los datos ya presentes en la DB

---

## Añadir un feed personalizado

### Formato TXT (una IP o dominio por línea)

Crea un feed en `feeds/feed_config.json`:

```json
{
  "id": "mi_feed",
  "name": "Mi Feed Personalizado",
  "provider": "MiOrganización",
  "url": "https://midominio.com/iocs.txt",
  "type": "CustomTxt",
  "format": "txt",
  "enabled": true,
  "ttl_hours": 12,
  "ioc_types": ["ip"]
}
```

### Formato CSV

```json
{
  "type": "CustomCsv",
  "format": "csv",
  "csv_fields": {
    "value_column": 0,
    "type_column": 1,
    "skip_rows": 1
  }
}
```

### Formato JSON

```json
{
  "type": "CustomJson",
  "format": "json",
  "json_path": "$.data[*].indicator"
}
```

---

## Falsos positivos

Los feeds de warninglists (MISP) actúan como listas blancas. Un IOC que aparece en una warninglist recibe `-20` en el scoring, reduciendo la probabilidad de falsa alarma.

Adicionalmente, el usuario puede:
- Añadir rutas a la lista de excepción en Configuración
- Usar "Añadir a lista blanca" en la vista de amenazas
- Bloquear manualmente un hash con `block_ioc`

---

## Privacidad

Ningún IOC consultado se envía a servidores externos. Toda la resolución se hace contra la cache SQLite local. Las actualizaciones de feeds son descargas unidireccionales (GET) sin enviar datos del sistema.
