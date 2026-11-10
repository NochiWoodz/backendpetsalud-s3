package com.petsalud.backendpetsalud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Respuestas uniformes (JSON) para 401 y 403 y registro de los accesos rechazados.
 * No se revelan detalles internos del motivo del rechazo.
 */
@Component
public class ManejadoresSeguridad implements AuthenticationEntryPoint, AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger("AUDITORIA_SEGURIDAD");
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException {
        log.warn("ACCESO_NO_AUTENTICADO metodo={} ruta={} ip={}", request.getMethod(),
                request.getRequestURI(), request.getRemoteAddr());
        response.setHeader("WWW-Authenticate", "Bearer");
        escribir(response, HttpStatus.UNAUTHORIZED, "Autenticación requerida", request);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException ex) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String usuario = auth == null ? "(anonimo)" : AuditoriaSeguridadListener.enmascarar(auth.getName());
        log.warn("ACCESO_DENEGADO usuario={} metodo={} ruta={} ip={}", usuario, request.getMethod(),
                request.getRequestURI(), request.getRemoteAddr());
        escribir(response, HttpStatus.FORBIDDEN, "No tiene permisos para este recurso", request);
    }

    private void escribir(HttpServletResponse response, HttpStatus estado, String mensaje,
                          HttpServletRequest request) throws IOException {
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("timestamp", LocalDateTime.now().toString());
        cuerpo.put("status", estado.value());
        cuerpo.put("error", estado.getReasonPhrase());
        cuerpo.put("mensaje", mensaje);
        cuerpo.put("ruta", request.getRequestURI());
        response.setStatus(estado.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), cuerpo);
    }
}
