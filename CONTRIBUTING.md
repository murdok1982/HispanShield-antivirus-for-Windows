# Contribuir a HispanShield

¡Gracias por tu interés en contribuir! HispanShield es un proyecto open-source de seguridad defensiva.

## Código de conducta

Sé respetuoso, constructivo y colaborativo. No se tolera el acoso ni el lenguaje ofensivo.

## Cómo contribuir

### 1. Fork y rama

```bash
git clone https://github.com/tu-usuario/hispanshield-antivirus.git
cd hispanshield-antivirus
git checkout -b feat/mi-mejora
```

### 2. Desarrolla tu cambio

Sigue los estándares del stack:
- **Rust**: `cargo clippy -- -D warnings`, `cargo fmt`
- **TypeScript**: ESLint + Prettier, `strict: true`

### 3. Commits (en español)

Formato: `tipo(scope): descripción breve`

| Tipo | Uso |
|---|---|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de bug |
| `refactor` | Refactorización sin cambio de comportamiento |
| `test` | Añadir o mejorar tests |
| `docs` | Documentación |
| `chore` | Tareas de mantenimiento |
| `security` | Mejoras de seguridad |
| `perf` | Mejoras de rendimiento |

Ejemplos:
```
feat(detection): añadir detección de doble extensión en FileMonitor
fix(ipc): corregir timeout en conexiones Named Pipe
security(quarantine): reforzar permisos DACL en directorio
docs(feeds): documentar formato de feed personalizado CSV
```

### 4. Pull Request

- Describe claramente qué cambia y por qué
- Referencia issues relacionados (`Fixes #123`)
- Incluye tests si aplica
- El CI debe pasar (build, clippy, tests)

---

## Añadir reglas YARA

1. Crea tu archivo `.yar` en `rules/community/` o `rules/hispan/`
2. Usa el formato de metadatos estándar:
   ```yara
   rule MiRegla {
       meta:
           description = "..."
           author      = "tu_nombre"
           severity    = "medium"  // low|medium|high|critical
           score       = 25
       strings:
           ...
       condition:
           ...
   }
   ```
3. Prueba que compile: `yarac tu_regla.yar /dev/null`
4. Documenta qué detecta y por qué no es un falso positivo común

## Añadir feeds OSINT

1. Añade la entrada en `feeds/feed_config.json`
2. Si el feed tiene un formato nuevo, implementa el parser en `agent/src/threat_intel/mod.rs`
3. Documenta el feed en `docs/threat-intel-feeds.md`
4. Verifica que el feed sea público, gratuito y de confianza

## Tests

```bash
# Tests del agente
cargo test -p hispanshield-agent

# Test específico
cargo test -p hispanshield-agent -- scoring::tests

# TypeScript
cd ui && npx tsc --noEmit
```

## Reportar vulnerabilidades

Ver [SECURITY.md](SECURITY.md) — **NO uses issues públicos** para bugs de seguridad.
