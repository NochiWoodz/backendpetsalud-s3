package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.CrearUsuarioInternoRequest;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Gestión de usuarios internos. La ruta /api/gerencia/** exige el rol GERENTE (ver SecurityConfig). */
@RestController
@RequestMapping("/api/gerencia/usuarios")
public class GerenciaUsuarioController {

    private final UsuarioService usuarioService;

    public GerenciaUsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    @PostMapping
    public ResponseEntity<Usuario> crearUsuario(@Valid @RequestBody CrearUsuarioInternoRequest req) {
        Usuario usuario = Usuario.builder()
                .email(req.email())
                .password(req.password())
                .nombre(req.nombre())
                .apellido(req.apellido())
                .telefono(req.telefono())
                .direccion(req.direccion())
                .rol(req.rol())
                .build();
        return ResponseEntity.status(HttpStatus.CREATED).body(usuarioService.registrarUsuario(usuario));
    }
}
