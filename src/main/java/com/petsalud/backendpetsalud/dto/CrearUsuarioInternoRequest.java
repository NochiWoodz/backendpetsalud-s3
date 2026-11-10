package com.petsalud.backendpetsalud.dto;

import com.petsalud.backendpetsalud.entity.Rol;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Alta de usuarios internos (empleados, gerentes). Solo accesible para GERENTE. */
public record CrearUsuarioInternoRequest(
        @NotBlank @Email @Size(max = 120) String email,

        @NotBlank
        @Size(min = 8, max = 64)
        @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
                message = "La contraseña debe incluir mayúscula, minúscula y número")
        String password,

        @NotBlank @Size(max = 60) String nombre,
        @NotBlank @Size(max = 60) String apellido,
        @Size(max = 20) String telefono,
        @Size(max = 200) String direccion,
        @NotNull(message = "El rol es obligatorio") Rol rol) {
}
