package com.petsalud.backendpetsalud;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pruebas de las amenazas comunes (Semana 3): inyección SQL, XSS y CSRF.
 * Cada prueba envía un ataque típico y verifica que el backend lo neutraliza.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AmenazasSeguridadTest {

    private static final String CLAVE = "Petsalud2025";

    @Autowired
    private MockMvc mvc;

    private String token(String email) throws Exception {
        String json = "{\"email\":\"" + email + "\",\"password\":\"" + CLAVE + "\"}";
        String cuerpo = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(cuerpo, "$.token");
    }

    private String registro(String email, String nombre, String direccion) {
        return "{\"email\":\"" + email + "\",\"password\":\"Segura123\",\"nombre\":\"" + nombre
                + "\",\"apellido\":\"Prueba\",\"direccion\":\"" + direccion + "\"}";
    }

    // ---------- Inyección SQL ----------

    @Test
    void sqlInjectionEnLoginNoOtorgaAcceso() throws Exception {
        String ataque = "{\"email\":\"' OR '1'='1' --\",\"password\":\"' OR '1'='1\"}";
        String cuerpo = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(ataque))
                .andExpect(status().is4xxClientError())
                .andReturn().getResponse().getContentAsString();
        assertFalse(cuerpo.contains("token"), "No debe emitirse token ante una inyección SQL");
    }

    @Test
    void sqlInjectionEnParametroDeConsultaSeTrataComoTexto() throws Exception {
        mvc.perform(get("/api/productos/categoria").param("categoria", "' OR '1'='1")
                        .header("Authorization", token("cliente@petsalud.cl")))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));
    }

    @Test
    void sqlInjectionEnIdDeRutaDevuelve400() throws Exception {
        mvc.perform(get("/api/usuarios/1 OR 1=1")
                        .header("Authorization", token("gerente@petsalud.cl")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void textoConSqlSeGuardaLiteralYLaTablaSigueIntacta() throws Exception {
        String gerente = token("gerente@petsalud.cl");
        String producto = "{\"nombre\":\"x'); DROP TABLE productos; --\",\"descripcion\":\"d\","
                + "\"precio\":1000,\"stock\":5,\"categoria\":\"prueba\"}";
        mvc.perform(post("/api/productos").header("Authorization", gerente)
                        .contentType(MediaType.APPLICATION_JSON).content(producto))
                .andExpect(status().is2xxSuccessful());
        mvc.perform(get("/api/productos").header("Authorization", gerente))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("DROP TABLE productos")));
    }

    // ---------- XSS ----------

    @Test
    void registroConEtiquetaScriptEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(registro("xss1@correo.cl", "<script>alert(1)</script>", "Calle 1")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void registroConEtiquetaConEventoEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(registro("xss2@correo.cl", "Ana", "<img src=x onerror=alert(1)>")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void esquemaJavascriptEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(registro("xss3@correo.cl", "Ana", "javascript:alert(1)")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void xssEnProductoCreadoPorGerenteEsRechazado() throws Exception {
        String producto = "{\"nombre\":\"<script>alert(1)</script>\",\"descripcion\":\"d\","
                + "\"precio\":1000,\"stock\":5,\"categoria\":\"prueba\"}";
        mvc.perform(post("/api/productos").header("Authorization", token("gerente@petsalud.cl"))
                        .contentType(MediaType.APPLICATION_JSON).content(producto))
                .andExpect(status().isBadRequest());
    }

    @Test
    void textoLegitimoConApostrofeYSimboloMenorSeAcepta() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content(registro("legitimo@correo.cl", "María O'Brien", "Av. Libertad 123, peso < 5 kg")))
                .andExpect(status().isCreated());
    }

    @Test
    void lasRespuestasLlevanCabecerasContraXssYClickjacking() throws Exception {
        mvc.perform(get("/api/productos").header("Authorization", token("cliente@petsalud.cl")))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", org.hamcrest.Matchers.startsWith("application/json")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy",
                        org.hamcrest.Matchers.containsString("default-src 'none'")));
    }

    // ---------- CSRF ----------

    @Test
    void peticionDeOtroOrigenSinTokenEsRechazada() throws Exception {
        String producto = "{\"nombre\":\"forjado\",\"descripcion\":\"d\",\"precio\":1,\"stock\":1,\"categoria\":\"x\"}";
        mvc.perform(post("/api/productos").header("Origin", "https://sitio-malicioso.example")
                        .contentType(MediaType.APPLICATION_JSON).content(producto))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unaCookieDeSesionNoAutenticaPeticiones() throws Exception {
        mvc.perform(get("/api/usuarios").header("Cookie", "JSESSIONID=ABC123"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void elLoginNoCreaCookiesDeSesion() throws Exception {
        String json = "{\"email\":\"cliente@petsalud.cl\",\"password\":\"" + CLAVE + "\"}";
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    // ---------- Fuga de información ----------

    @Test
    void loginFallidoNoRevelaSiElUsuarioExiste() throws Exception {
        String existente = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"cliente@petsalud.cl\",\"password\":\"Incorrecta1\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Credenciales inválidas"))
                .andReturn().getResponse().getContentAsString();
        String inexistente = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nadie@petsalud.cl\",\"password\":\"Incorrecta1\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Credenciales inválidas"))
                .andReturn().getResponse().getContentAsString();
        assertFalse(existente.isEmpty() || inexistente.isEmpty());
    }
}
