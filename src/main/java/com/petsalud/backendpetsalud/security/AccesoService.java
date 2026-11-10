package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Reglas de autorización a nivel de objeto (propiedad del recurso).
 * Se usa desde @PreAuthorize("... @acceso.esMismoUsuario(#id, authentication)").
 * Evita el acceso a datos de otros clientes (IDOR / Broken Access Control).
 */
@Component("acceso")
public class AccesoService {

    private final MascotaRepository mascotaRepository;
    private final NotificacionRepository notificacionRepository;

    public AccesoService(MascotaRepository mascotaRepository, NotificacionRepository notificacionRepository) {
        this.mascotaRepository = mascotaRepository;
        this.notificacionRepository = notificacionRepository;
    }

    public boolean esMismoUsuario(Long usuarioId, Authentication auth) {
        return usuarioId != null && auth != null
                && auth.getPrincipal() instanceof UsuarioDetails d
                && usuarioId.equals(d.getId());
    }

    public boolean esPropietarioDeMascota(Long mascotaId, Authentication auth) {
        if (mascotaId == null) {
            return false;
        }
        return mascotaRepository.findById(mascotaId)
                .map(m -> m.getPropietario() != null && esMismoUsuario(m.getPropietario().getId(), auth))
                .orElse(false);
    }

    public boolean esDuenoDeNotificacion(Long notificacionId, Authentication auth) {
        if (notificacionId == null) {
            return false;
        }
        return notificacionRepository.findById(notificacionId)
                .map(n -> n.getUsuario() != null && esMismoUsuario(n.getUsuario().getId(), auth))
                .orElse(false);
    }
}
