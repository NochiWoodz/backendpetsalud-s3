package com.petsalud.backendpetsalud.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Credenciales para iniciar sesión. */
public record LoginRequest(
        @NotBlank(message = "El email es obligatorio")
        @Size(max = 120, message = "El email es demasiado largo")
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(max = 64, message = "La contraseña es demasiado larga")
        String password) {
}
