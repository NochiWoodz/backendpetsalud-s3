package com.petsalud.backendpetsalud.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/** Respuestas de error uniformes que no filtran detalles internos (trazas, SQL, clases). */
@RestControllerAdvice
public class ManejadorErrores {

    private static final Logger AUDITORIA = LoggerFactory.getLogger("AUDITORIA_SEGURIDAD");

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> validacion(MethodArgumentNotValidException ex) {
        Map<String, String> campos = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(e -> campos.put(e.getField(), e.getDefaultMessage()));
        Map<String, Object> cuerpo = base(HttpStatus.BAD_REQUEST, "Datos de entrada inválidos");
        cuerpo.put("campos", campos);
        return ResponseEntity.badRequest().body(cuerpo);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> argumentoInvalido(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(base(HttpStatus.BAD_REQUEST, ex.getMessage()));
    }

    /** JSON mal formado o con contenido rechazado por la sanitización (HTML/script): no se detalla el motivo. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> cuerpoIlegible(HttpMessageNotReadableException ex) {
        AUDITORIA.warn("evento=ENTRADA_RECHAZADA motivo=cuerpo-no-valido-o-contenido-peligroso");
        return ResponseEntity.badRequest().body(base(HttpStatus.BAD_REQUEST, "Cuerpo de la solicitud inválido"));
    }

    /** Parámetro o id con tipo incorrecto (por ejemplo "1 OR 1=1" en lugar de un número). */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> tipoIncorrecto(MethodArgumentTypeMismatchException ex) {
        AUDITORIA.warn("evento=ENTRADA_RECHAZADA motivo=tipo-incorrecto parametro={}", ex.getName());
        return ResponseEntity.badRequest().body(base(HttpStatus.BAD_REQUEST, "Parámetro inválido"));
    }

    /** Credenciales inválidas o cuenta bloqueada: mismo mensaje para no revelar qué falló. */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> autenticacion(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer")
                .body(base(HttpStatus.UNAUTHORIZED, "Credenciales inválidas"));
    }

    private Map<String, Object> base(HttpStatus estado, String mensaje) {
        Map<String, Object> cuerpo = new LinkedHashMap<>();
        cuerpo.put("timestamp", LocalDateTime.now().toString());
        cuerpo.put("status", estado.value());
        cuerpo.put("mensaje", mensaje);
        return cuerpo;
    }
}
