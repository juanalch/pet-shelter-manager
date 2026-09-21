package com.shelter.app;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
                        "('ana', '" + md5("perritos2024") + "')");
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
     * [VULN-4] CWE-327 / CWE-916: Use of a Broken or Risky Cryptographic
     * Algorithm. MD5 es rápido y sin salt -> trivialmente crackeable por
     * fuerza bruta / rainbow tables. Debería usarse BCrypt/Argon2 con salt
     * (p.ej. Spring Security's BCryptPasswordEncoder).
     */
    public static String md5(String input) {                                    // [VULN-4]
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");                 // [VULN-4]
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
