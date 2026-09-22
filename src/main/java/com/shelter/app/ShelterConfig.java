package com.shelter.app;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * [FIX VULN-3] CWE-798 — corregido en Ronda 2.
 *
 * Antes: la contraseña de admin, la API key de backups y el secreto de
 * firma estaban escritos en texto plano en este archivo (quemados en el
 * código fuente), visibles para cualquiera con acceso al repositorio.
 *
 * Ahora: los tres valores se inyectan desde application.properties con
 * @Value, y application.properties a su vez los toma de variables de
 * entorno del sistema operativo (ver ${ADMIN_PASSWORD}, etc. en ese
 * archivo). El código fuente ya no contiene ningún secreto real.
 *
 * Si una variable de entorno requerida no está definida, la aplicación
 * falla al arrancar (fail-fast) en vez de arrancar con un secreto vacío
 * o un valor por defecto inseguro.
 */
@Component
public class ShelterConfig implements InitializingBean {

    @Value("${shelter.admin.username}")
    private String adminUsername;

    @Value("${shelter.admin.password}")
    private String adminPassword;

    @Value("${shelter.backup.api-key}")
    private String backupServiceApiKey;

    @Value("${shelter.jwt.secret}")
    private String jwtSigningSecret;

    @Override
    public void afterPropertiesSet() {
        requireNonBlank(adminPassword, "ADMIN_PASSWORD");
        requireNonBlank(backupServiceApiKey, "BACKUP_SERVICE_API_KEY");
        requireNonBlank(jwtSigningSecret, "JWT_SIGNING_SECRET");
    }

    private void requireNonBlank(String value, String envVarName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException(
                    "Falta la variable de entorno " + envVarName +
                    ". Defínela antes de arrancar la aplicación (ver README).");
        }
    }

    public String getAdminUsername() {
        return adminUsername;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public String getBackupServiceApiKey() {
        return backupServiceApiKey;
    }

    public String getJwtSigningSecret() {
        return jwtSigningSecret;
    }
}