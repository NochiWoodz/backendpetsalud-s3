package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Creación y validación de tokens JWT firmados (JWS) con HMAC-SHA256 (HS256).
 * <ul>
 *   <li>La clave secreta se recibe en Base64 por configuración (variable de entorno JWT_SECRET en
 *       producción) y debe tener al menos 256 bits; si no, la aplicación no inicia.</li>
 *   <li>Claims: sub (email), uid, roles, iss, iat, exp y jti (identificador único).</li>
 *   <li>La validación verifica firma, emisor y expiración. Un token sin firma ("alg":"none") o
 *       firmado con otro algoritmo es rechazado.</li>
 * </ul>
 */
@Component
public class JwtUtil {

    private final SecretKey clave;
    private final String emisor;
    private final Duration expiracion;

    public JwtUtil(@Value("${petsalud.jwt.secret}") String secretBase64,
                   @Value("${petsalud.jwt.issuer:petsalud-backend}") String emisor,
                   @Value("${petsalud.jwt.expiracion-minutos:30}") long expiracionMinutos) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(secretBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("petsalud.jwt.secret debe estar codificado en Base64");
        }
        if (bytes.length < 32) {
            throw new IllegalStateException("petsalud.jwt.secret debe tener al menos 256 bits (32 bytes)");
        }
        this.clave = Keys.hmacShaKeyFor(bytes);
        this.emisor = emisor;
        this.expiracion = Duration.ofMinutes(expiracionMinutos);
    }

    /** Genera un token firmado para el usuario autenticado. */
    public String generarToken(UserDetails usuario) {
        Instant ahora = Instant.now();
        List<String> roles = usuario.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        Long uid = usuario instanceof UsuarioDetails d ? d.getId() : null;
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(emisor)
                .subject(usuario.getUsername())
                .claim("uid", uid)
                .claim("roles", roles)
                .issuedAt(Date.from(ahora))
                .expiration(Date.from(ahora.plus(expiracion)))
                .signWith(clave) // HS256 con una clave de 256 bits
                .compact();
    }

    /**
     * Valida firma, emisor y expiración, y devuelve los claims.
     *
     * @throws JwtException             si el token está mal formado, manipulado, expirado o sin firma
     * @throws IllegalArgumentException si el token es nulo o vacío
     */
    public Claims validarYObtenerClaims(String token) {
        return Jwts.parser()
                .verifyWith(clave)
                .requireIssuer(emisor)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean esValido(String token) {
        try {
            validarYObtenerClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public long getExpiracionSegundos() {
        return expiracion.toSeconds();
    }
}
