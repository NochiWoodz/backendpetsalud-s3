package com.petsalud.backendpetsalud.config;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Crea tres usuarios de demostración (uno por rol) cuando la base está vacía.
 * Solo se activa con petsalud.seed.enabled=true (por defecto en desarrollo).
 * Las contraseñas se guardan con BCrypt, nunca en texto plano.
 */
@Configuration
public class DataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    @Bean
    CommandLineRunner cargarUsuariosDemo(UsuarioRepository repo, PasswordEncoder encoder,
                                         @Value("${petsalud.seed.enabled:false}") boolean habilitado,
                                         @Value("${petsalud.seed.password:}") String password) {
        return args -> {
            if (!habilitado || password.isBlank() || repo.count() > 0) {
                return;
            }
            crear(repo, encoder, password, "gerente@petsalud.cl", "Ana", "Gerente", Rol.GERENTE);
            crear(repo, encoder, password, "empleado@petsalud.cl", "Victor", "Empleado", Rol.EMPLEADO);
            crear(repo, encoder, password, "cliente@petsalud.cl", "Carla", "Cliente", Rol.CLIENTE);
            log.info("Usuarios de demostración creados (gerente, empleado, cliente @petsalud.cl)");
        };
    }

    private void crear(UsuarioRepository repo, PasswordEncoder encoder, String password,
                       String email, String nombre, String apellido, Rol rol) {
        repo.save(Usuario.builder()
                .email(email)
                .password(encoder.encode(password))
                .nombre(nombre)
                .apellido(apellido)
                .rol(rol)
                .build());
    }
}
