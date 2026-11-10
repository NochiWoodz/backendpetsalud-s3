package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Adaptador entre la entidad {@link Usuario} y el contrato {@link UserDetails} de Spring Security.
 * El rol se expone con el prefijo ROLE_ para poder usar hasRole()/hasAnyRole().
 */
public class UsuarioDetails implements UserDetails {

    private final Usuario usuario;
    private final boolean cuentaBloqueada;

    public UsuarioDetails(Usuario usuario, boolean cuentaBloqueada) {
        this.usuario = usuario;
        this.cuentaBloqueada = cuentaBloqueada;
    }

    public Long getId() {
        return usuario.getId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + usuario.getRol().name()));
    }

    @Override
    public String getPassword() {
        return usuario.getPassword();
    }

    @Override
    public String getUsername() {
        return usuario.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !cuentaBloqueada;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
