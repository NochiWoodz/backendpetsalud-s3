package com.petsalud.backendpetsalud;

import com.jayway.jsonpath.JsonPath;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.UsuarioDetails;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Pruebas de integración: login con JWT, filtro de validación y autorización por rol. */
@SpringBootTest
@AutoConfigureMockMvc
class AuthIntegracionTest {

    private static final String CLAVE = "Petsalud2025";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Value("${petsalud.jwt.secret}")
    private String secretoJwt;

    private String login(String email, String clave) throws Exception {
        String json = "{\"email\":\"" + email + "\",\"password\":\"" + clave + "\"}";
        String cuerpo = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(cuerpo, "$.token");
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    // ---------- Autenticación ----------

    @Test
    void loginCorrectoDevuelveTokenBearerYRol() throws Exception {
        String json = "{\"email\":\"cliente@petsalud.cl\",\"password\":\"" + CLAVE + "\"}";
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tipo").value("Bearer"))
                .andExpect(jsonPath("$.rol").value("CLIENTE"))
                .andExpect(jsonPath("$.expiraEnSegundos").value(1800));
    }

    @Test
    void loginConClaveIncorrectaDevuelve401SinToken() throws Exception {
        String json = "{\"email\":\"cliente@petsalud.cl\",\"password\":\"ClaveErronea1\"}";
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    void loginConUsuarioInexistenteDevuelveElMismoError() throws Exception {
        String json = "{\"email\":\"nadie@petsalud.cl\",\"password\":\"ClaveErronea1\"}";
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensaje").value("Credenciales inválidas"));
    }

    @Test
    void cuentaSeBloqueaTrasVariosIntentosFallidos() throws Exception {
        String registro = "{\"email\":\"bloqueo@correo.cl\",\"password\":\"Segura123\",\"nombre\":\"Bea\",\"apellido\":\"Test\"}";
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON).content(registro))
                .andExpect(status().isCreated());
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"bloqueo@correo.cl\",\"password\":\"Mala" + i + "Clave\"}"))
                    .andExpect(status().isUnauthorized());
        }
        // Con la clave correcta, la cuenta sigue bloqueada
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"bloqueo@correo.cl\",\"password\":\"Segura123\"}"))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Filtro JWT ----------

    @Test
    void sinTokenDevuelve401() throws Exception {
        mvc.perform(get("/api/productos"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"));
    }

    @Test
    void conTokenValidoSePuedeAccederAlRecurso() throws Exception {
        String token = login("cliente@petsalud.cl", CLAVE);
        mvc.perform(get("/api/productos").header("Authorization", bearer(token)))
                .andExpect(status().isOk());
    }

    @Test
    void perfilDevuelveLosDatosDelUsuarioDelToken() throws Exception {
        String token = login("empleado@petsalud.cl", CLAVE);
        mvc.perform(get("/api/auth/perfil").header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("empleado@petsalud.cl"))
                .andExpect(jsonPath("$.rol").value("EMPLEADO"));
    }

    @Test
    void tokenManipuladoDevuelve401() throws Exception {
        String[] partes = login("cliente@petsalud.cl", CLAVE).split("\\.");
        char original = partes[1].charAt(5);
        char cambiado = original == 'A' ? 'B' : 'A';
        String alterado = partes[0] + "." + partes[1].substring(0, 5) + cambiado + partes[1].substring(6) + "." + partes[2];
        mvc.perform(get("/api/productos").header("Authorization", bearer(alterado)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenSinFirmaDevuelve401() throws Exception {
        String sinFirma = Jwts.builder().subject("gerente@petsalud.cl").issuer("petsalud-backend").compact();
        mvc.perform(get("/api/usuarios").header("Authorization", bearer(sinFirma)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenExpiradoDevuelve401() throws Exception {
        var usuario = usuarioRepository.findByEmail("cliente@petsalud.cl").orElseThrow();
        String expirado = new JwtUtil(secretoJwt, "petsalud-backend", -1)
                .generarToken(new UsuarioDetails(usuario, false));
        mvc.perform(get("/api/productos").header("Authorization", bearer(expirado)))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Autorización por rol ----------

    @Test
    void clienteNoPuedeListarUsuarios() throws Exception {
        mvc.perform(get("/api/usuarios").header("Authorization", bearer(login("cliente@petsalud.cl", CLAVE))))
                .andExpect(status().isForbidden());
    }

    @Test
    void empleadoNoPuedeListarUsuarios() throws Exception {
        mvc.perform(get("/api/usuarios").header("Authorization", bearer(login("empleado@petsalud.cl", CLAVE))))
                .andExpect(status().isForbidden());
    }

    @Test
    void gerentePuedeListarUsuariosYNoVeLaContrasena() throws Exception {
        mvc.perform(get("/api/usuarios").header("Authorization", bearer(login("gerente@petsalud.cl", CLAVE))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].email").exists())
                .andExpect(jsonPath("$[0].password").doesNotExist());
    }

    @Test
    void clienteNoPuedeCrearProductos() throws Exception {
        String json = "{\"nombre\":\"Collar\",\"precio\":5990,\"stock\":10,\"categoria\":\"Accesorios\"}";
        mvc.perform(post("/api/productos").header("Authorization", bearer(login("cliente@petsalud.cl", CLAVE)))
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isForbidden());
    }

    @Test
    void clienteNoPuedeVerLosDatosDeOtroUsuario() throws Exception {
        long idGerente = usuarioRepository.findByEmail("gerente@petsalud.cl").orElseThrow().getId();
        mvc.perform(get("/api/usuarios/" + idGerente)
                        .header("Authorization", bearer(login("cliente@petsalud.cl", CLAVE))))
                .andExpect(status().isForbidden());
    }

    @Test
    void clientePuedeVerSusPropiosDatos() throws Exception {
        long idCliente = usuarioRepository.findByEmail("cliente@petsalud.cl").orElseThrow().getId();
        mvc.perform(get("/api/usuarios/" + idCliente)
                        .header("Authorization", bearer(login("cliente@petsalud.cl", CLAVE))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    // ---------- Registro y alta de personal ----------

    @Test
    void registroPublicoSiempreCreaCliente_aunqueSeEnvieRolGerente() throws Exception {
        String json = "{\"email\":\"nuevo@correo.cl\",\"password\":\"Segura123\",\"nombre\":\"Nora\","
                + "\"apellido\":\"Test\",\"rol\":\"GERENTE\"}";
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.rol").value("CLIENTE"))
                .andExpect(jsonPath("$.password").doesNotExist());

        var guardado = usuarioRepository.findByEmail("nuevo@correo.cl").orElseThrow();
        assertEquals(Rol.CLIENTE, guardado.getRol());
        // La contraseña se almacena como hash BCrypt, no en texto plano
        assertNotEquals("Segura123", guardado.getPassword());
        assertTrue(guardado.getPassword().startsWith("$2"));
    }

    @Test
    void registroConContrasenaDebilDevuelve400() throws Exception {
        String json = "{\"email\":\"debil@correo.cl\",\"password\":\"123\",\"nombre\":\"A\",\"apellido\":\"B\"}";
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.campos.password").exists());
    }

    @Test
    void soloElGerentePuedeCrearEmpleados() throws Exception {
        String json = "{\"email\":\"nuevo.empleado@petsalud.cl\",\"password\":\"Segura123\",\"nombre\":\"Eva\","
                + "\"apellido\":\"Vet\",\"rol\":\"EMPLEADO\"}";
        mvc.perform(post("/api/gerencia/usuarios").header("Authorization", bearer(login("cliente@petsalud.cl", CLAVE)))
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isForbidden());

        mvc.perform(post("/api/gerencia/usuarios").header("Authorization", bearer(login("gerente@petsalud.cl", CLAVE)))
                        .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.rol").value("EMPLEADO"));

        // El nuevo empleado puede iniciar sesión y su token lleva el rol EMPLEADO
        String cuerpo = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nuevo.empleado@petsalud.cl\",\"password\":\"Segura123\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("EMPLEADO", JsonPath.read(cuerpo, "$.rol"));
    }
}
