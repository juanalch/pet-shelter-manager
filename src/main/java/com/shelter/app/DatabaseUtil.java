package com.shelter.app;

import org.springframework.security.crypto.bcrypt.BCrypt;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseUtil {

    private static final String DB_PATH = "shelter.db";
    private static final String DB_URL = "jdbc:sqlite:" + DB_PATH;

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    public static void initDb() {
        boolean isNew = !new File(DB_PATH).exists();
        try (Connection conn = getConnection(); Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS volunteers (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT UNIQUE," +
                    "password_hash TEXT)");
            st.execute("CREATE TABLE IF NOT EXISTS pets (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT," +
                    "species TEXT," +
                    "notes TEXT)");

            if (isNew) {
                st.execute("INSERT INTO volunteers (username, password_hash) VALUES " +
                        "('ana', '" + hashPassword("perritos2024") + "')"); // [FIX VULN-4]
                st.execute("INSERT INTO pets (name, species, notes) VALUES " +
                        "('Firulais','Perro','Vacunado, muy jugueton')," +
                        "('Michi','Gato','Timido, en observacion')," +
                        "('Piolin','Ave','Recien llegado')");
            }
        } catch (SQLException e) {
            throw new RuntimeException("No se pudo inicializar la base de datos", e);
        }
    }

    /**
     * [FIX VULN-4] CWE-327 / CWE-916 — corregido en Ronda 1.
     * Antes se usaba MD5 (rápido, sin sal, crackeable por fuerza bruta o
     * rainbow tables). Ahora se usa BCrypt: cada llamada a hashPassword()
     * genera una sal aleatoria distinta (BCrypt.gensalt()) y produce un
     * hash lento por diseño, lo que hace impráctico el crackeo masivo
     * incluso si la base de datos se filtra (p. ej. vía una SQLi como la
     * de VULN-1, ya corregida también en esta ronda).
     */
    public static String hashPassword(String plainPassword) {                    // [FIX VULN-4]
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt());
    }

    public static boolean checkPassword(String plainPassword, String storedHash) { // [FIX VULN-4]
        return BCrypt.checkpw(plainPassword, storedHash);
    }
}
