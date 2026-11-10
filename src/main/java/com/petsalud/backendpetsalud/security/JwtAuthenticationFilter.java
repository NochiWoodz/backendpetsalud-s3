package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro que intercepta cada petición, extrae el token del encabezado "Authorization: Bearer ..."
 * y lo valida ANTES de la autenticación estándar (se registra antes de
 * UsernamePasswordAuthenticationFilter). Si el token es válido, carga al usuario desde la base
 * de datos y deja la autenticación en el SecurityContext solo durante esa petición.
 * Si no hay token o es inválido, no autentica: el acceso lo rechaza la configuración
 * de autorización con 401. No se registra como bean para evitar su doble registro como filtro de servlet.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("AUDITORIA_SEGURIDAD");
    private static final String PREFIJO = "Bearer ";

    private final JwtUtil jwtUtil;
    private final UsuarioDetailsService usuarioDetailsService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UsuarioDetailsService usuarioDetailsService) {
        this.jwtUtil = jwtUtil;
        this.usuarioDetailsService = usuarioDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String encabezado = request.getHeader("Authorization");
        if (encabezado != null && encabezado.startsWith(PREFIJO)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = encabezado.substring(PREFIJO.length()).trim();
            try {
                Claims claims = jwtUtil.validarYObtenerClaims(token);
                UserDetails usuario = usuarioDetailsService.loadUserByUsername(claims.getSubject());
                Object uid = claims.get("uid");
                // El token debe corresponder al mismo usuario que hoy existe en la base de datos
                if (usuario instanceof UsuarioDetails d && uid instanceof Number n && d.getId().equals(n.longValue())) {
                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } else {
                    log.warn("TOKEN_RECHAZADO motivo=identidad_no_coincide metodo={} ruta={} ip={}",
                            request.getMethod(), request.getRequestURI(), request.getRemoteAddr());
                }
            } catch (JwtException | IllegalArgumentException | UsernameNotFoundException e) {
                SecurityContextHolder.clearContext();
                log.warn("TOKEN_INVALIDO motivo={} metodo={} ruta={} ip={}", e.getClass().getSimpleName(),
                        request.getMethod(), request.getRequestURI(), request.getRemoteAddr());
            }
        }
        chain.doFilter(request, response);
    }
}
