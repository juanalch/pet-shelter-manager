package com.shelter.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Pet Shelter Manager
 * --------------------
 * App de gestión de un refugio de mascotas: registro de voluntarios,
 * búsqueda/adopción de mascotas, generación de reportes veterinarios
 * y descarga de fotos/documentos.
 *
 * ⚠️ PROYECTO ACADEMICO — CONTIENE VULNERABILIDADES INTENCIONALES
 *    Laboratorio de DevSecOps / SAST. NO usar en producción.
 *    Cada bloque vulnerable está marcado con [VULN-N] y su CWE.
 */
@SpringBootApplication
public class PetShelterManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(PetShelterManagerApplication.class, args);
    }
}
