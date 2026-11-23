# Simulador de Evaluación de Riesgos y Auditoría de Ciberseguridad para Infraestructuras TI

**Entregable N° 2 (Modo Consola)** — Proyecto académico desarrollado en Java estándar (sin dependencias externas), alineado 1:1 con el Diagrama de Clases UML (Punto 6) y la estructura de paquetes (Punto 7) del documento del proyecto.

## Integrantes y Módulos
- **Módulo 1 — Inventario de Activos y Puertos:** Egas Kevin (`GestorInventario`)
- **Módulo 2 — Catálogo de Vulnerabilidades y CVSS:** Cáseres Jardi (`MotorCVSS`)
- **Módulo 3 — Topología y Propagación de Ataques:** Albiño Alexis (`SimuladorPropagacion`)
- **Módulo 4 — Plan de Mitigación y Presupuesto:** Fiallos Christian (`OptimizadorMitigacion`)
- **Módulo 5 — Reportes de Cumplimiento y Auditoría:** Yunga César (`AuditoriaService`)

## Estructura de Paquetes (`src/`)
- `com.auditoria.Main`: Punto de entrada, inicialización de módulos y precarga PYME.
- `com.auditoria.modelo`: `ActivoRed` (abstracta), `Servidor`, `EstacionTrabajo`, `DispositivoRed`, `PuertoServicio`, `Vulnerabilidad`, `EnlaceRed`, `AccionMitigacion`, `ReporteAuditoria`.
- `com.auditoria.negocio`: `GestorInventario`, `MotorCVSS`, `SimuladorPropagacion`, `OptimizadorMitigacion`, `AuditoriaService`.
- `com.auditoria.util`: `ValidadorDatos`, `AuditoriaException`, `DatosIniciales`.
- `com.auditoria.interfaz`: `MenuConsola`.

## Compilación, Pruebas y Empaquetado (`.jar` ejecutable)

Desde la carpeta `SimuladorRiesgosTI`:

```bash
chmod +x build.sh
./build.sh
```

Para ejecutar la aplicación empaquetada:

```bash
java -jar dist/SimuladorCiberseguridad.jar
```

### Abrir en IntelliJ IDEA
1. Abrir la carpeta `SimuladorRiesgosTI` en IntelliJ IDEA (`File -> Open`).
2. Verificar que `Project SDK` esté configurado (Java 21+ / 25).
3. Ejecutar `com.auditoria.Main`.
