# Política de Seguridad — HispanShield Antivirus

## Versiones soportadas

| Versión | Soporte de seguridad |
|---|---|
| 0.1.x | Activo |

---

## Reporte de vulnerabilidades

**NO abras un issue público** para reportar una vulnerabilidad de seguridad.

Envía un correo a **gustavolobatoclara@gmail.com** con el asunto:
`[HispanShield Security] Descripción breve`

Incluye:
- Descripción detallada de la vulnerabilidad
- Pasos para reproducirla
- Impacto potencial
- Versión afectada
- Sugerencia de fix (opcional)

**Tiempo de respuesta esperado**: 48-72 horas para confirmar recepción.

---

## Scope

### En scope
- Vulnerabilidades en el agente Rust (`agent/`)
- Vulnerabilidades en el dashboard Tauri (`ui/`)
- Problemas de autenticación en el IPC
- Escape de cuarentena
- Elevación de privilegios no intencionada
- Vulnerabilidades en el procesamiento de feeds OSINT

### Fuera de scope
- Ataques que requieren acceso físico al equipo
- Ataques que requieren privilegios de Administrador o SYSTEM previos
- Ingeniería social
- Denegación de servicio local
- Limitaciones inherentes a no tener driver kernel (documentadas)

---

## Principios de seguridad del proyecto

1. **Sin secrets en código** — toda configuración sensible en `%ProgramData%\HispanShield\`
2. **IPC autenticado** — token HMAC-SHA256 por sesión
3. **Permisos mínimos** — el agente corre como LocalSystem solo donde es necesario
4. **Sin acceso remoto** — el agente solo escucha en un Named Pipe local
5. **Cuarentena aislada** — permisos DACL restringidos al servicio
6. **Logs inmutables** — los logs de eventos tienen integridad básica
