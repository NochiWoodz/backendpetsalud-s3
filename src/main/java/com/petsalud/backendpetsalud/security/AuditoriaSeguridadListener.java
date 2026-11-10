package com.petsalud.backendpetsalud.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Registro de eventos de seguridad (requisito: "monitorear y registrar actividades sospechosas").
 * Escucha los eventos que publica Spring Security, lleva la cuenta de fallos por usuario y deja
 * trazas en el log. Por protección de datos personales NO se registran contraseñas y el email
 * se enmascara.
 */
@Component
public class AuditoriaSeguridadListener {

    private static final Logger log = LoggerFactory.getLogger("AUDITORIA_SEGURIDAD");

    private final IntentosLoginService intentosLoginService;

    public AuditoriaSeguridadListener(IntentosLoginService intentosLoginService) {
        this.intentosLoginService = intentosLoginService;
    }

    @EventListener
    public void alAutenticarse(AuthenticationSuccessEvent evento) {
        String usuario = evento.getAuthentication().getName();
        intentosLoginService.registrarExito(usuario);
        log.info("LOGIN_OK usuario={}", enmascarar(usuario));
    }

    @EventListener
    public void alFallar(AbstractAuthenticationFailureEvent evento) {
        Authentication auth = evento.getAuthentication();
        String usuario = auth.getName();
        if (!(evento instanceof AuthenticationFailureLockedEvent)) {
            intentosLoginService.registrarFallo(usuario);
        }
        log.warn("LOGIN_FALLIDO usuario={} motivo={}", enmascarar(usuario),
                evento.getException().getClass().getSimpleName());
    }

    public static String enmascarar(String email) {
        if (email == null || email.isBlank()) {
            return "(vacio)";
        }
        int arroba = email.indexOf('@');
        if (arroba <= 1) {
            return "***";
        }
        return email.charAt(0) + "***" + email.substring(arroba);
    }
}
