package com.petsalud.backendpetsalud.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.deser.std.StringDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Defensa en profundidad contra XSS almacenado: toda cadena que llegue en un cuerpo JSON se revisa
 * antes de asignarse a un DTO o entidad. Se rechaza (400) el texto que contenga etiquetas HTML
 * ("&lt;script&gt;", "&lt;img ...&gt;") o el esquema "javascript:". Un texto como "peso &lt; 5 kg" es válido.
 * La defensa principal sigue siendo codificar la salida en el cliente y las cabeceras de seguridad.
 */
@Configuration
public class SanitizacionEntrada {

    static final Pattern CONTENIDO_PELIGROSO =
            Pattern.compile("<\\s*/?\\s*[a-zA-Z!?]|javascript\\s*:", Pattern.CASE_INSENSITIVE);

    @Bean
    public Module moduloSanitizacionEntrada() {
        SimpleModule modulo = new SimpleModule("SanitizacionEntrada");
        modulo.addDeserializer(String.class, new StringSeguroDeserializer());
        return modulo;
    }

    static class StringSeguroDeserializer extends StdDeserializer<String> {

        StringSeguroDeserializer() {
            super(String.class);
        }

        @Override
        public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            if (!p.hasToken(JsonToken.VALUE_STRING)) {
                return StringDeserializer.instance.deserialize(p, ctxt);
            }
            String valor = p.getText();
            if (valor != null && CONTENIDO_PELIGROSO.matcher(valor).find()) {
                return (String) ctxt.handleWeirdStringValue(String.class, "[contenido omitido]",
                        "El campo contiene HTML o script no permitido");
            }
            return valor;
        }
    }
}
