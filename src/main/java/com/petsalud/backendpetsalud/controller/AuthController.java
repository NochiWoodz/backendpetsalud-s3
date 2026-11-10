package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.LoginRequest;
import com.petsalud.backendpetsalud.dto.LoginResponse;
import com.petsalud.backendpetsalud.dto.RegistroUsuarioRequest;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.UsuarioDetails;
import com.petsalud.backendpetsalud.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** Registro de clientes, inicio de sesión (emite el JWT) y consulta del perfil autenticado. */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UsuarioService usuarioService;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil,
                          UsuarioService usuarioService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.usuarioService = usuarioService;
    }

    /** Registro público: el rol lo fija el servidor (siempre CLIENTE). */
    @PostMapping("/registro")
    public ResponseEntity<Usuario> registrar(@Valid @RequestBody RegistroUsuarioRequest req) {
        Usuario usuario = Usuario.builder()
                .email(req.email())
                .password(req.password())
                .nombre(req.nombre())
                .apellido(req.apellido())
                .telefono(req.telefono())
                .direccion(req.direccion())
                .rol(Rol.CLIENTE)
                .build();
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.registrarUsuario(usuario));
    }

    /**
     * Valida las credenciales (BCrypt contra la base de datos) y, si son correctas, emite un JWT.
     * Ante credenciales inválidas o cuenta bloqueada, ManejadorErrores responde 401 genérico.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.email(), req.password()));
        UsuarioDetails usuario = (UsuarioDetails) auth.getPrincipal();
        String token = jwtUtil.generarToken(usuario);
        return ResponseEntity.ok(new LoginResponse(token, "Bearer", jwtUtil.getExpiracionSegundos(),
                usuario.getUsername(), rolDe(usuario)));
    }

    /** Devuelve los datos del usuario identificado por el token. */
    @GetMapping("/perfil")
    public Map<String, Object> perfil(Authentication auth) {
        UsuarioDetails usuario = (UsuarioDetails) auth.getPrincipal();
        Map<String, Object> perfil = new LinkedHashMap<>();
        perfil.put("id", usuario.getId());
        perfil.put("email", usuario.getUsername());
        perfil.put("rol", rolDe(usuario));
        return perfil;
    }

    private static String rolDe(UsuarioDetails usuario) {
        return usuario.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
    }
}
