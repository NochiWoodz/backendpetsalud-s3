package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.service.MascotaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/mascotas")
public class MascotaController {

    @Autowired
    private MascotaService mascotaService;

    @PreAuthorize("hasRole('GERENTE') or @acceso.esMismoUsuario(#propietarioId, authentication)")
    @PostMapping("/propietario/{propietarioId}")
    public ResponseEntity<Mascota> registrarMascota(@PathVariable Long propietarioId, @RequestBody Mascota mascota) {
        Mascota nuevaMascota = mascotaService.registrarMascota(mascota, propietarioId);
        return ResponseEntity.ok(nuevaMascota);
    }

    @PreAuthorize("hasAnyRole('EMPLEADO','GERENTE') or @acceso.esPropietarioDeMascota(#id, authentication)")
    @GetMapping("/{id}")
    public ResponseEntity<Mascota> obtenerMascotaPorId(@PathVariable Long id) {
        return mascotaService.obtenerMascotaPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasAnyRole('EMPLEADO','GERENTE') or @acceso.esPropietarioDeMascota(#id, authentication)")
    @PutMapping("/{id}")
    public ResponseEntity<Mascota> actualizarMascota(@PathVariable Long id, @RequestBody Mascota mascota) {
        Mascota mascotaActualizada = mascotaService.actualizarMascota(id, mascota);
        return ResponseEntity.ok(mascotaActualizada);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarMascota(@PathVariable Long id) {
        mascotaService.eliminarMascota(id);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasAnyRole('EMPLEADO','GERENTE') or @acceso.esMismoUsuario(#propietarioId, authentication)")
    @GetMapping("/propietario/{propietarioId}")
    public ResponseEntity<List<Mascota>> listarMascotasPorPropietario(@PathVariable Long propietarioId) {
        List<Mascota> mascotas = mascotaService.listarMascotasPorPropietario(propietarioId);
        return ResponseEntity.ok(mascotas);
    }
}
