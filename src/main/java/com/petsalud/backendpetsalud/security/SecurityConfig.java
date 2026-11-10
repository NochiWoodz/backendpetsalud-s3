package com.petsalud.backendpetsalud.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Configuración de Spring Security para el backend de Clínica PetSalud (Semana 2: JWT).
 * <ul>
 *   <li>Se reemplaza la configuración por defecto de Spring Boot (login por formulario, HTTP Basic y
 *       usuario generado) por una cadena de filtros propia (bean SecurityFilterChain).</li>
 *   <li>Autenticación: el cliente inicia sesión en /api/auth/login y recibe un JWT que envía en
 *       cada petición con "Authorization: Bearer". Sesión STATELESS.</li>
 *   <li>JwtAuthenticationFilter valida el token antes de UsernamePasswordAuthenticationFilter.</li>
 *   <li>Contraseñas: hash BCrypt. Autorización: por rol (CLIENTE, EMPLEADO, GERENTE) por URL y por
 *       propiedad del recurso con @PreAuthorize.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtUtil jwtUtil,
                                                   UsuarioDetailsService usuarioDetailsService,
                                                   ManejadoresSeguridad manejadores) throws Exception {
        http
                // API REST sin estado: el JWT viaja en el encabezado Authorization (no en una cookie), el
                // navegador no lo adjunta de forma automática, por lo que no aplica el ataque CSRF clásico.
                // Si el token se guardara en una cookie, CSRF debe reactivarse.
                .csrf(AbstractHttpConfigurer::disable)
                // Se deshabilita la autenticación por defecto de Spring Security
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Público: únicamente registro de clientes e inicio de sesión
                        .requestMatchers(HttpMethod.POST, "/api/auth/registro", "/api/auth/login").permitAll()

                        // Administración
                        .requestMatchers("/api/gerencia/**").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/usuarios").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.DELETE, "/api/usuarios/*").hasRole("GERENTE")
                        // GET/PUT /api/usuarios/{id}: dueño o GERENTE (ver @PreAuthorize)

                        // Productos: lectura para cualquier usuario autenticado, escritura solo GERENTE
                        .requestMatchers(HttpMethod.POST, "/api/productos/**").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.PUT, "/api/productos/**").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.DELETE, "/api/productos/**").hasRole("GERENTE")

                        // Ventas
                        .requestMatchers(HttpMethod.POST, "/api/ventas").hasAnyRole("CLIENTE", "GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/ventas").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/ventas/*").hasRole("GERENTE")

                        // Datos clínicos: solo personal clínico; el dueño ve los de su mascota (@PreAuthorize)
                        .requestMatchers(HttpMethod.GET, "/api/expedientes/mascota/*").authenticated()
                        .requestMatchers("/api/expedientes/**").hasAnyRole("EMPLEADO", "GERENTE")

                        // Citas
                        .requestMatchers(HttpMethod.POST, "/api/citas").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/citas/mascota/*").authenticated()
                        .requestMatchers("/api/citas/**").hasAnyRole("EMPLEADO", "GERENTE")

                        // Mascotas
                        .requestMatchers(HttpMethod.DELETE, "/api/mascotas/*").hasRole("GERENTE")

                        // Notificaciones y recompensas
                        .requestMatchers(HttpMethod.GET, "/api/notificaciones/usuario/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/notificaciones/*/leida").authenticated()
                        .requestMatchers("/api/notificaciones/**").hasRole("GERENTE")
                        .requestMatchers(HttpMethod.GET, "/api/recompensas/usuario/*").authenticated()
                        .requestMatchers("/api/recompensas/**").hasRole("GERENTE")

                        // Denegar por defecto: todo lo demás exige autenticación
                        .anyRequest().authenticated()
                )
                // El filtro JWT se ejecuta antes de la autenticación estándar de usuario/contraseña
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil, usuarioDetailsService),
                        UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(manejadores)
                        .accessDeniedHandler(manejadores))
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                        .frameOptions(f -> f.deny())
                        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .httpStrictTransportSecurity(Customizer.withDefaults())
                );

        return http.build();
    }

    /** Gestor de autenticación usado por /api/auth/login (UsuarioDetailsService + BCrypt). */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuracion) throws Exception {
        return configuracion.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
