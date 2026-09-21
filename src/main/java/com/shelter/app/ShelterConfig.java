package com.shelter.app;

/**
 * [VULN-3] CWE-798: Use of Hard-coded Credentials
 * Contraseña de administrador y API key de un servicio externo
 * (limpieza/backup de la base de datos) quemadas en el código fuente.
 * Cualquiera con acceso al repositorio (o al .jar/.war compilado, vía
 * decompile) obtiene ambas credenciales. Un SAST (Snyk, SonarCloud,
 * gitleaks, trufflehog) lo detecta como "hardcoded secret".
 */
public class ShelterConfig {

    public static final String ADMIN_USERNAME = "admin";
    public static final String ADMIN_PASSWORD = "Admin123!";                              // [VULN-3]

    // Luce como una API key real de un proveedor de backups en la nube
    public static final String BACKUP_SERVICE_API_KEY = "sk_live_51Nf8x9pQwErTyUiOpAsDfGhJk"; // [VULN-3]

    public static final String JWT_SIGNING_SECRET = "sh3lt3r-super-secret-2024";           // [VULN-3]
}
