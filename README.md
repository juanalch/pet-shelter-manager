# 🐾 Pet Shelter Manager (Java / Spring Boot)

Aplicación de gestión de un refugio de mascotas: registro de voluntarios,
búsqueda de mascotas, generación de reportes veterinarios y descarga de
fotos/documentos.

> ⚠️ **PROYECTO ACADÉMICO — Laboratorio de DevSecOps / SAST**
> Este repositorio contiene **vulnerabilidades plantadas intencionalmente**
> con fines educativos (análisis estático de seguridad). **No desplegar
> en producción ni exponer a internet.**

## Stack

- Java 8 + Spring Boot 2.1.6 (Web + Thymeleaf)
- SQLite (vía `sqlite-jdbc`)
- Maven

## Cómo correr

```bash
mvn spring-boot:run
# http://localhost:8080
```

Usuario de prueba: `ana` / `perritos2024`
Admin (credencial quemada a propósito): `admin` / `Admin123!`

## Vulnerabilidades plantadas (baseline `v0-vulnerable`)

| # | CWE | OWASP Top 10 | Archivo / línea | Descripción |
|---|-----|---------------|------------------|-------------|
| 1 | CWE-89 — SQL Injection | A03:2021 Injection | `ShelterController.java`, método `search()` | El parámetro `q` se concatena directo en el SQL (`Statement` en vez de `PreparedStatement`). Permite `UNION SELECT` sobre la tabla `volunteers` para robar hashes de contraseñas. |
| 2 | CWE-78 — OS Command Injection | A03:2021 Injection | `ShelterController.java`, método `generateReport()` | El nombre de la mascota se inyecta en un comando `sh -c` ejecutado con `Runtime.exec()`. Permite ejecución de comandos arbitrarios en el servidor. |
| 3 | CWE-798 — Hard-coded Credentials | A07:2021 Identification and Authentication Failures | `ShelterConfig.java` | Contraseña de admin, API key de un servicio de backups y secreto de firma de sesión quemados en el código fuente. |
| 4 | CWE-327 / CWE-916 — Broken/Risky Crypto Algorithm | A02:2021 Cryptographic Failures | `DatabaseUtil.java`, método `md5()` | Las contraseñas de voluntarios se hashean con MD5 sin salt: crackeable por fuerza bruta / rainbow tables. |
| 5 | CWE-22 — Path Traversal | A01:2021 Broken Access Control | `ShelterController.java`, método `download()` | El parámetro `file` se concatena al path de `uploads/` sin normalizar ni validar (`../../../etc/passwd`). |
| 6 | CWE-1104 / CWE-937 — Use of Component with Known Vulnerabilities | A06:2021 Vulnerable and Outdated Components | `pom.xml` | Spring Boot 2.1.6.RELEASE y Jackson Databind 2.9.8 fijados a propósito: versiones con CVEs públicos conocidos en su cadena de dependencias. |

## Notas para el triage (EX·05)

Al conectar el repo a Snyk/SonarCloud es normal que también aparezcan
hallazgos "extra" no listados aquí (por ejemplo, falta de CSRF protection
por defecto de Spring Security al no estar incluido, o el manejo de
excepciones silencioso en `search()`). Documenten esos como parte del
triage: son reales, simplemente no fueron plantados a propósito — igual
cuentan como hallazgo válido si deciden corregirlos.

## Remediaciones sugeridas (para el "after")

1. **SQLi** → usar `PreparedStatement` con parámetros en todas las consultas.
2. **Command Injection** → eliminar el `Runtime.exec`/shell; si es
   estrictamente necesario, usar `ProcessBuilder` con lista de argumentos
   (sin `sh -c`) y una whitelist de caracteres para `petName`.
3. **Hard-coded secrets** → mover a variables de entorno / `application.yml`
   fuera del control de versiones, o a un vault (AWS Secrets Manager,
   HashiCorp Vault).
4. **MD5** → migrar a `BCryptPasswordEncoder` (Spring Security) con salt
   automático y factor de costo configurable.
5. **Path Traversal** → resolver el path con `Paths.get(UPLOAD_DIR, file).normalize()`
   y verificar que el resultado siga dentro de `UPLOAD_DIR` (`startsWith`).
6. **Dependencias** → actualizar a la última versión estable de Spring Boot
   2.7.x/3.x y Jackson Databind, y activar Dependabot/Renovate.
