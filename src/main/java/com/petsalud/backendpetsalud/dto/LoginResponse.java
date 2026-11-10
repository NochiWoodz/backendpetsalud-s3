package com.petsalud.backendpetsalud.dto;

/** Respuesta de un inicio de sesión exitoso. El token se envía luego como "Authorization: Bearer". */
public record LoginResponse(String token, String tipo, long expiraEnSegundos, String email, String rol) {
}
