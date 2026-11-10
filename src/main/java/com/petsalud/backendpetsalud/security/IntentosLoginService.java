package com.petsalud.backendpetsalud.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Control de intentos fallidos de autenticación (mitigación de fuerza bruta).
 * Tras N fallos consecutivos la cuenta se bloquea temporalmente.
 * Implementación en memoria: suficiente para una instancia; en un despliegue con varias
 * instancias debería moverse a un almacén compartido (por ejemplo Redis).
 */
@Service
public class IntentosLoginService {

    private record Registro(int fallos, Instant bloqueadoHasta) {
    }

    private final Map<String, Registro> registros = new ConcurrentHashMap<>();
    private final int maxIntentos;
    private final Duration bloqueo;

    public IntentosLoginService(
            @Value("${petsalud.seguridad.max-intentos:5}") int maxIntentos,
            @Value("${petsalud.seguridad.bloqueo-minutos:15}") long bloqueoMinutos) {
        this.maxIntentos = maxIntentos;
        this.bloqueo = Duration.ofMinutes(bloqueoMinutos);
    }

    private static String clave(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    public void registrarFallo(String email) {
        registros.compute(clave(email), (k, actual) -> {
            int fallos = (actual == null ? 0 : actual.fallos()) + 1;
            Instant hasta = fallos >= maxIntentos ? Instant.now().plus(bloqueo) : null;
            return new Registro(fallos, hasta);
        });
    }

    public void registrarExito(String email) {
        registros.remove(clave(email));
    }

    public boolean estaBloqueado(String email) {
        Registro r = registros.get(clave(email));
        if (r == null || r.bloqueadoHasta() == null) {
            return false;
        }
        if (Instant.now().isAfter(r.bloqueadoHasta())) {
            registros.remove(clave(email));
            return false;
        }
        return true;
    }
}
