package com.shelter.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpSession;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Controller
public class ShelterController {

    static { DatabaseUtil.initDb(); }

    @Autowired
    private ShelterConfig shelterConfig;

    private static final String UPLOAD_DIR = "uploads/";

    @GetMapping("/")
    public String home() {
        return "index";
    }

    // -------------------------------------------------------------------
    // LOGIN
    // -------------------------------------------------------------------
    @GetMapping("/login")
    public String loginForm(Model model) {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                         @RequestParam String password,
                         HttpSession session,
                         Model model) {

        if (shelterConfig.ADMIN_USERNAME.equals(username)
                && shelterConfig.ADMIN_PASSWORD.equals(password)) {
            session.setAttribute("user", "admin");
            return "redirect:/dashboard";
        }

        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT password_hash FROM volunteers WHERE username = ?")) {
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            if (rs.next() && DatabaseUtil.checkPassword(password, rs.getString(1))) { // [FIX VULN-4]
                session.setAttribute("user", username);
                return "redirect:/dashboard";
            }
        } catch (SQLException e) {
            model.addAttribute("error", "Error interno");
            return "login";
        }

        model.addAttribute("error", "Credenciales invalidas");
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        Object user = session.getAttribute("user");
        if (user == null) return "redirect:/login";
        model.addAttribute("user", user);
        return "dashboard";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    // -------------------------------------------------------------------
    // [FIX VULN-1] CWE-89: SQL Injection — corregido en Ronda 1
    // Se reemplazó la concatenación de `q` dentro del SQL por un
    // PreparedStatement con parámetro (`?`). El driver JDBC se encarga de
    // escapar el valor, por lo que `q` ya no puede alterar la estructura
    // de la consulta (p. ej. un UNION SELECT ya no funciona).
    // Cierra también el hallazgo de SonarQube "dynamically formatted SQL
    // query" reportado sobre esta misma línea.
    // -------------------------------------------------------------------
    @GetMapping("/search")
    public String search(@RequestParam(defaultValue = "") String q, Model model) {
        List<String[]> results = new ArrayList<>();
        String sql = "SELECT id, name, species, notes FROM pets WHERE name LIKE ?"; // [FIX VULN-1]

        try (Connection conn = DatabaseUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {                    // [FIX VULN-1]
            ps.setString(1, "%" + q + "%");                                          // [FIX VULN-1]
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                results.add(new String[]{
                        rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)
                });
            }
        } catch (SQLException e) {
            // ya no se ignora en silencio: se registra para diagnóstico,
            // sin exponer el stacktrace al usuario final
            System.err.println("Error en /search: " + e.getMessage());
        }

        model.addAttribute("results", results);
        model.addAttribute("query", q);
        return "search";
    }

    // -------------------------------------------------------------------
    // Se genera el archivo directamente con Java, sin invocar un shell ni
    // interpolar petName en un comando del sistema.
    // -------------------------------------------------------------------
    @PostMapping("/generate-report")
    @ResponseBody
    public ResponseEntity<String> generateReport(@RequestParam String petName,
                                                  HttpSession session) throws Exception {
        if (session.getAttribute("user") == null) {                              // [FIX] CWE-306
            return ResponseEntity.status(401).body("No autenticado");
        }

        Path reportsDir = Paths.get(UPLOAD_DIR, "reports");
        Files.createDirectories(reportsDir);
        Path report = reportsDir.resolve("report_" + UUID.randomUUID() + ".txt");
        Files.write(report, ("Reporte veterinario de " + petName).getBytes(StandardCharsets.UTF_8));
        return ResponseEntity.ok("Reporte generado para " + HtmlUtils.htmlEscape(petName));
    }

    // -------------------------------------------------------------------
    // [FIX VULN-5] CWE-22: Path Traversal — corregido en Ronda 1
    // Se resuelve `file` contra el directorio base con Path.resolve() y
    // se normaliza con normalize() para colapsar secuencias "..". Luego
    // se verifica explícitamente que la ruta resultante siga estando
    // DENTRO de UPLOAD_DIR (startsWith sobre las rutas absolutas). Si el
    // intento de escape se detecta, se responde 400 en vez de revelar si
    // el archivo objetivo existe o no, lo que también cierra el hallazgo
    // "Filesystem Oracle" reportado por SonarQube sobre este endpoint.
    // -------------------------------------------------------------------
    @GetMapping("/download")
    @ResponseBody
    public ResponseEntity<Resource> download(@RequestParam String file) {
        Path baseDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();     // [FIX VULN-5]
        Path target = baseDir.resolve(file).normalize();                      // [FIX VULN-5]

        if (!target.startsWith(baseDir)) {                                    // [FIX VULN-5]
            return ResponseEntity.badRequest().build();
        }
        if (!Files.exists(target)) {
            return ResponseEntity.notFound().build();
        }
        Resource resource = new FileSystemResource(target.toFile());
        return ResponseEntity.ok(resource);
    }
}
