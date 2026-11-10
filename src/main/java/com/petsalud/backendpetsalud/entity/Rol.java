package com.petsalud.backendpetsalud.entity;

/**
 * Roles del sistema.
 * CLIENTE: dueño de mascotas. EMPLEADO: personal de la clínica (veterinarios y atención).
 * GERENTE: administración de la clínica (máximo privilegio).
 */
public enum Rol {
    CLIENTE,
    EMPLEADO,
    GERENTE
}
