package com.petsalud.backendpetsalud.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Datos de registro de un cliente. No incluye el rol: todo registro público se crea como CLIENTE,
 * lo que evita la escalada de privilegios (mass assignment).
 */
public record RegistroUsuarioRequest(
        @NotBlank(message = "El email es obligatorio")
        @Email(message = "El email no tiene un formato válido")
        @Size(max = 120, message = "El email es demasiado largo")
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 8, max = 64, message = "La contraseña debe tener entre 8 y 64 caracteres")
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
                message = "La contraseña debe incluir mayúscula, minúscula y número")
        String password,

        @NotBlank(message = "El nombre es obligatorio")
        @Size(max = 60, message = "El nombre es demasiado largo")
        String nombre,

        @NotBlank(message = "El apellido es obligatorio")
        @Size(max = 60, message = "El apellido es demasiado largo")
        String apellido,

        @Size(max = 20, message = "El teléfono es demasiado largo")
        String telefono,

        @Size(max = 200, message = "La dirección es demasiado larga")
        String direccion) {
}
