# Build e Instalación — HispanShield

## Prerrequisitos

| Herramienta | Versión | Link |
|---|---|---|
| Rust + Cargo | ≥ 1.78 stable | https://rustup.rs |
| Node.js | ≥ 20 LTS | https://nodejs.org |
| Visual Studio Build Tools | 2022 | https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022 |
| YARA | ≥ 4.5 | `choco install yara` o compilar desde fuente |
| WiX Toolset | ≥ 4.0 (opcional, para MSI) | https://wixtoolset.org |

### Configurar Rust para Windows

```powershell
rustup default stable
rustup target add x86_64-pc-windows-msvc
```

### Variables de entorno para YARA

```powershell
$env:YARA_INCLUDE_DIR = "C:\yara\include"
$env:YARA_LIB_DIR = "C:\yara\lib"
```

---

## Build del agente Rust

```powershell
# Debug (más rápido, logs detallados)
cargo build -p hispanshield-agent

# Release (optimizado para producción)
cargo build --release -p hispanshield-agent
```

El binario resultante se encuentra en:
- Debug: `target\debug\hispanshield-agent.exe`
- Release: `target\release\hispanshield-agent.exe`

### Ejecutar tests

```powershell
cargo test -p hispanshield-agent
cargo clippy -p hispanshield-agent -- -D warnings
```

---

## Build del dashboard (Tauri + React)

```powershell
cd ui

# Instalar dependencias Node.js
npm install

# Modo desarrollo (abre ventana Tauri en vivo)
npm run tauri dev

# Build de producción
npm run tauri build
```

El instalador MSI resultante se encuentra en:
`ui\src-tauri\target\release\bundle\msi\HispanShield_0.1.0_x64_en-US.msi`

---

## Build completo (script automático)

```powershell
# Desde la raíz del repositorio (como Administrador)
.\installer\scripts\build.ps1

# Solo el agente:
.\installer\scripts\build.ps1 -SkipUI

# Solo la UI:
.\installer\scripts\build.ps1 -SkipAgent
```

---

## Instalación

### Opción 1: Instalador MSI (recomendado)

Ejecuta el instalador generado en `installer\build\HispanShield-0.1.0.msi`.

El instalador:
1. Instala los binarios en `C:\Program Files\HispanShield\`
2. Crea directorio de datos en `C:\ProgramData\HispanShield\`
3. Genera el token IPC
4. Registra e inicia el servicio Windows
5. Crea accesos directos

### Opción 2: Script PowerShell manual

```powershell
# Como Administrador
.\installer\scripts\install.ps1 -InstallDir "C:\Program Files\HispanShield"
```

### Verificar la instalación

```powershell
# Ver estado del servicio
Get-Service HispanShieldAgent

# Ver logs del servicio
Get-EventLog -LogName Application -Source HispanShieldAgent -Newest 20

# Verificar que el pipe existe
[System.IO.Directory]::GetFiles("\\.\pipe\", "HispanShield*")
```

---

## Configuración inicial

La configuración se crea automáticamente en:
`C:\ProgramData\HispanShield\config.toml`

Valores por defecto:
- Protección en tiempo real: **activada**
- Acción ante amenaza: **Cuarentenar**
- Actualización de feeds: **cada 6 horas**
- Nivel de alerta: score ≥ **30**

---

## Actualización

Para actualizar a una versión nueva:

```powershell
# Detener servicio
Stop-Service HispanShieldAgent

# Copiar nuevos binarios
Copy-Item target\release\hispanshield-agent.exe "C:\Program Files\HispanShield\bin\" -Force

# Reiniciar servicio
Start-Service HispanShieldAgent
```

Con el instalador MSI, simplemente ejecuta el nuevo MSI — detecta la versión anterior y la actualiza.

---

## Desinstalación

```powershell
# Con el script (elimina todo excepto logs y cuarentena)
.\installer\scripts\install.ps1 -Uninstall

# O manualmente:
Stop-Service HispanShieldAgent
sc.exe delete HispanShieldAgent
Remove-Item "C:\Program Files\HispanShield" -Recurse -Force
# Los datos (cuarentena, logs) se conservan en C:\ProgramData\HispanShield\
```

---

## Troubleshooting

### El servicio no inicia

```powershell
# Ver logs de Windows
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "HispanShieldAgent"} | Select-Object -First 10

# Ver logs propios
Get-Content "C:\ProgramData\HispanShield\logs\hispanshield-agent.log" -Tail 50
```

### Error "Cannot connect to agent pipe"

1. Verifica que el servicio esté corriendo: `Get-Service HispanShieldAgent`
2. Verifica el token IPC: `Get-Content "C:\ProgramData\HispanShield\ipc_token"`
3. El token en `%ProgramData%\HispanShield\ipc_token` debe coincidir con el que usa el dashboard

### Error de compilación YARA

Asegúrate de que las variables `YARA_INCLUDE_DIR` y `YARA_LIB_DIR` apuntan a la instalación correcta.

```powershell
# Verificar que libyara.lib existe
Test-Path "$env:YARA_LIB_DIR\libyara.lib"
```
