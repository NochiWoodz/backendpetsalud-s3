package com.petsalud.backendpetsalud;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.UsuarioDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Pruebas unitarias de JwtUtil: claims, firma, expiración, emisor y algoritmo. */
class JwtUtilTest {

    private static final String EMISOR = "petsalud-backend";
    private static final String SECRETO = Base64.getEncoder()
            .encodeToString("0123456789abcdef0123456789abcdef".getBytes());
    private static final String OTRO_SECRETO = Base64.getEncoder()
            .encodeToString("ZYXWVUTSRQPONMLKJIHGFEDCBA987654".getBytes());

    private UsuarioDetails usuario() {
        Usuario u = Usuario.builder().id(7L).email("ana@petsalud.cl").password("hash").rol(Rol.CLIENTE).build();
        return new UsuarioDetails(u, false);
    }

    @Test
    void tokenGeneradoContieneLosClaimsEsperados() {
        JwtUtil jwt = new JwtUtil(SECRETO, EMISOR, 30);
        Claims claims = jwt.validarYObtenerClaims(jwt.generarToken(usuario()));

        assertEquals("ana@petsalud.cl", claims.getSubject());
        assertEquals(EMISOR, claims.getIssuer());
        assertEquals(7, ((Number) claims.get("uid")).intValue());
        assertEquals(List.of("ROLE_CLIENTE"), claims.get("roles"));
        assertNotNull(claims.getId());
        assertNotNull(claims.getIssuedAt());
        assertTrue(claims.getExpiration().after(claims.getIssuedAt()));
        // El token no debe llevar la contraseña ni su hash
        assertFalse(claims.containsKey("password"));
    }

    @Test
    void tokenManipuladoEsRechazado() {
        JwtUtil jwt = new JwtUtil(SECRETO, EMISOR, 30);
        String[] partes = jwt.generarToken(usuario()).split("\\.");
        // Se altera el contenido (payload) manteniendo la firma original
        char original = partes[1].charAt(5);
        char cambiado = original == 'A' ? 'B' : 'A';
        String payloadAlterado = partes[1].substring(0, 5) + cambiado + partes[1].substring(6);
        assertFalse(jwt.esValido(partes[0] + "." + payloadAlterado + "." + partes[2]));
    }

    @Test
    void tokenFirmadoConOtraClaveEsRechazado() {
        String token = new JwtUtil(OTRO_SECRETO, EMISOR, 30).generarToken(usuario());
        assertFalse(new JwtUtil(SECRETO, EMISOR, 30).esValido(token));
    }

    @Test
    void tokenExpiradoEsRechazado() {
        String token = new JwtUtil(SECRETO, EMISOR, -1).generarToken(usuario());
        assertFalse(new JwtUtil(SECRETO, EMISOR, 30).esValido(token));
    }

    @Test
    void tokenDeOtroEmisorEsRechazado() {
        String token = new JwtUtil(SECRETO, "otro-sistema", 30).generarToken(usuario());
        assertFalse(new JwtUtil(SECRETO, EMISOR, 30).esValido(token));
    }

    @Test
    void tokenSinFirmaAlgNoneEsRechazado() {
        String sinFirma = Jwts.builder().subject("ana@petsalud.cl").issuer(EMISOR).compact();
        assertFalse(new JwtUtil(SECRETO, EMISOR, 30).esValido(sinFirma));
    }

    @Test
    void tokenVacioOMalFormadoEsRechazado() {
        JwtUtil jwt = new JwtUtil(SECRETO, EMISOR, 30);
        assertFalse(jwt.esValido(""));
        assertFalse(jwt.esValido("esto.no.es.un.jwt"));
    }

    @Test
    void claveInsegura_impideIniciarLaAplicacion() {
        String corta = Base64.getEncoder().encodeToString("clave-corta".getBytes());
        assertThrows(IllegalStateException.class, () -> new JwtUtil(corta, EMISOR, 30));
        assertThrows(IllegalStateException.class, () -> new JwtUtil("%%no-es-base64%%", EMISOR, 30));
    }
}
