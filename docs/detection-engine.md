# Motor de Detección — HispanShield

## Capas de detección

HispanShield usa detección por capas. Cada capa contribuye al score final del IOC.

### 1. Hash Matching
Calcula SHA-256, SHA-1 y MD5 del archivo y consulta la cache local de IOCs.

Fuentes: MalwareBazaar, ThreatFox, feeds personalizados.

Peso en scoring: `+90` (hash en feed malicioso)

### 2. YARA Rules
Escanea el contenido del archivo con reglas YARA compiladas.

Categorías incluidas:
- LOLBins (`rules/hispan/lolbins.yar`)
- C2 frameworks (`rules/hispan/network.yar`)
- Indicadores de ransomware
- Credenciales comprometidas

Peso: `+80` (match fuerte) / `+40` (match débil)

### 3. Heurísticas estáticas
Análisis de rutas, extensiones, firma digital y contexto de ejecución.

| Condición | Score |
|---|---|
| Ejecutable en `Temp` o `%APPDATA%\Local\Temp` | +20 |
| Ejecutable en `AppData\Roaming` | +15 |
| Sin firma digital | +15 |
| Doble extensión (`.pdf.exe`, `.doc.exe`) | +30 |
| Ruta con caracteres Unicode sospechosos | +25 |

### 4. Comportamiento de proceso
Análisis del árbol de procesos y comportamiento en tiempo de ejecución.

| Condición | Score |
|---|---|
| Parent process sospechoso (Office → PowerShell) | +20 |
| LOLBin con argumentos sospechosos | +25 |
| Acceso masivo a archivos (>50 en 10s) | +40 |
| Modificación de archivos con extensiones de ransomware | +50 |
| Creación de nota de rescate | +50 |

### 5. Análisis de red
Correlación de conexiones con IOCs de red.

| Condición | Score |
|---|---|
| Conexión a IP en lista de C2 | +70 |
| Dominio en lista de malware | +70 |
| Beaconing (>10 conexiones al mismo host en 60s) | +30 |
| Puerto no estándar (<1024 o >49151 poco común) | +20 |

---

## Tabla de scoring completa

| Factor | Score | Descripción |
|---|---|---|
| `hash_in_feed` | +90 | Hash del archivo en feed malicioso |
| `yara_match_strong` | +80 | Match de regla YARA de alta severidad |
| `connection_to_ioc` | +70 | Conexión a IP/dominio malicioso |
| `yara_match_weak` | +40 | Match de regla YARA de baja severidad |
| `mass_file_modification` | +40 | >50 archivos modificados en 10 segundos |
| `autorun_persistence` | +35 | Escritura en claves Run/RunOnce/Startup |
| `beaconing` | +30 | Conexiones repetitivas al mismo destino |
| `exec_from_temp` | +20 | Ejecutable lanzado desde directorio temporal |
| `suspicious_parent` | +20 | Proceso padre inusual para el contexto |
| `rare_port_connection` | +20 | Conexión a puerto no habitual |
| `lolbin_suspicious` | +25 | LOLBin con argumentos maliciosos |
| `no_digital_signature` | +15 | Binario sin firma digital |
| `exec_from_appdata` | +15 | Ejecutable en AppData\Roaming |
| `valid_signature_trusted` | -30 | Firmado por CA reconocida + ruta confiable |
| `misp_allowlist` | -20 | En lista blanca MISP Warninglists |

**El score final se recorta entre 0 y 100.**

---

## Niveles de riesgo

| Score | Nivel | Color | Acción por defecto |
|---|---|---|---|
| 0 – 29 | Limpio | Verde | Ninguna |
| 30 – 59 | Sospechoso | Amarillo | Alertar |
| 60 – 79 | Alto riesgo | Naranja | Cuarentenar (configurable) |
| 80 – 100 | Crítico / Malicioso | Rojo | Cuarentenar + Alertar |

---

## LOLBins monitorizados

| Binario | Tipo de abuso detectado |
|---|---|
| `powershell.exe` | `-EncodedCommand`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass` |
| `cmd.exe` | Lanzado desde procesos no habituales, redirección sospechosa |
| `wscript.exe` | Descarga remota, ejecución desde temp |
| `cscript.exe` | Igual que wscript |
| `mshta.exe` | Carga de URL HTTP/HTTPS, VBScript, JavaScript |
| `rundll32.exe` | DLL desde rutas temporales |
| `regsvr32.exe` | Squiblydoo (scrobj.dll), URLs remotas |
| `certutil.exe` | `-decode`, `-urlcache -split` |
| `bitsadmin.exe` | `/transfer`, `/create`, `/addfile` |
| `msiexec.exe` | Instalación desde URL remota |
| `cmstp.exe` | Bypass de AppLocker |
| `wmic.exe` | Ejecución remota de procesos |

---

## Detección de comportamiento ransomware

HispanShield detecta patrones de comportamiento que sugieren ransomware en curso:

1. **Modificación masiva**: >50 archivos modificados en <10 segundos → score +40
2. **Extensiones de cifrado**: `.locked`, `.encrypted`, `.enc`, `.crypted` → score +50
3. **Nota de rescate**: archivos con nombres como `HOW_TO_DECRYPT.txt`, `README_RANSOMWARE.html` → score +50
4. **Shadow copies**: ejecución de `vssadmin delete shadows` → score +70
5. **Escalada de privilegios**: process injection en LSASS, token duplication

---

## Reglas YARA personalizadas

Coloca archivos `.yar` en `rules/community/` o `rules/hispan/`. El agente carga y compila todas las reglas al iniciar.

Formato de metadatos recomendado:
```yara
rule MiReglaPersonalizada
{
    meta:
        description = "Descripción de lo que detecta"
        author      = "Tu nombre"
        severity    = "high"   // low | medium | high | critical
        score       = 40       // contribución al scoring
        tags        = "tag1,tag2"
    strings:
        $s1 = "cadena de texto" ascii nocase
    condition:
        $s1
}
```

---

## Reducción de falsos positivos

- **MISP Warninglists**: dominios e IPs de servicios populares (Microsoft, Google, Akamai, Alexa Top 1M) → reducen score en -20
- **Lista de excepción local**: rutas configuradas por el usuario en Ajustes
- **Firma digital válida + ruta de sistema**: reduce score en -30
- **Hash en allowlist**: anula completamente la detección
