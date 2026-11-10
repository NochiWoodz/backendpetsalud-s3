package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Autenticación contra base de datos: busca al usuario por email y entrega sus credenciales
 * (hash BCrypt) y su rol a Spring Security.
 */
@Service
public class UsuarioDetailsService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;
    private final IntentosLoginService intentosLoginService;

    public UsuarioDetailsService(UsuarioRepository usuarioRepository, IntentosLoginService intentosLoginService) {
        this.usuarioRepository = usuarioRepository;
        this.intentosLoginService = intentosLoginService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Credenciales inválidas"));
        return new UsuarioDetails(usuario, intentosLoginService.estaBloqueado(email));
    }
}
