package io.jzheaux.springsecurity.goals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.Filter;
import java.util.List;
import java.util.UUID;

import static io.jzheaux.springsecurity.goals.ReflectionSupport.annotation;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print= MockMvcPrint.NONE)
@SpringBootTest
public class Module3_Tests {
    @Autowired
    MockMvc mvc;

    @Autowired(required = false)
    FilterChainProxy springSecurityFilterChain;

    @Autowired(required = false)
    CorsConfigurationSource cors;

    @Autowired(required = false)
    Jwt jwt;

    @Autowired(required = false)
    OpaqueTokenIntrospector introspector;

    @Before
    public void setup() {
        assertNotNull(
                "Module 1: Could not find the Spring Security Filter Chain in the application context;" +
                        "make sure that you complete the earlier modules before starting this one",
                this.springSecurityFilterChain);
    }

    @TestConfiguration
    static class TestConfig {

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")
        @Bean
        JwtDecoder jwtDecoder() {
            return NimbusJwtDecoder
                    .withJwkSetUri("https://idp.example.org/jwks")
                    .build();
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
        @Bean
        JwtDecoder interrim() {
            return token -> {
                throw new BadJwtException("bad jwt");
            };
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri")
        @ConditionalOnMissingBean
        @Bean
        OpaqueTokenIntrospector introspector(OAuth2ResourceServerProperties properties) {
            return new NimbusOpaqueTokenIntrospector(
                    properties.getOpaquetoken().getIntrospectionUri(),
                    properties.getOpaquetoken().getClientId(),
                    properties.getOpaquetoken().getClientSecret());
        }

    }

    private void _task_1() {
        // add @CrossOrigin

        CrossOrigin crossOrigin = annotation(CrossOrigin.class, "read");
        assertNotNull(
                "Task 1: Please add the `@CrossOrigin` annotation to the `GoalController#read` method",
                crossOrigin);
    }

    @Test
    public void task_1() {
        _task_1();
        // cors()

        CorsFilter filter = getFilter(CorsFilter.class);
        assertNotNull(
                "Task 2: It doesn't appear that `cors()` is being called on the `HttpSecurity` object. If it is, make " +
                "sure that `GoalsApplication` is extending `WebSecurityConfigurerAdapter` and is overriding `configure(HttpSecurity http)`",
                filter);
    }

    @Test
    public void task_2() throws Exception {
        task_1();

        CrossOrigin crossOrigin = annotation(CrossOrigin.class, "read");
        if (this.jwt == null && this.introspector == null) { // Compatibility with Module 6, which shuts this field off
            assertEquals(
                    "Task 4: So that HTTP Basic works in the browser for this request, set the `allowCredentials` property on the `@CrossOrigin` annotation to `\"true\"`",
                    "true", crossOrigin.allowCredentials()
            );
        }

        MvcResult result = this.mvc.perform(options("/goals")
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Origin", "http://localhost:8081"))
                .andReturn();

        if (this.jwt == null && this.introspector == null) { // Compatibility with Module 6, which shuts this field off
            assertEquals(
                    "Task 4: Tried to do an `OPTIONS` pre-flight request from `http://localhost:8081` for `GET /goals` failed.",
                    "true", result.getResponse().getHeader("Access-Control-Allow-Credentials"));
        }

        result = this.mvc.perform(options("/" + UUID.randomUUID())
                .header("Access-Control-Request-Method", "HEAD")
                .header("Access-Control-Allow-Credentials", "true")
                .header("Origin", "http://localhost:8081"))
                .andReturn();

        if (this.jwt == null && this.introspector == null) { // Compatibility with Module 6, which shuts this field off
            assertNotEquals(
                    "Task 4: Tried to do an `OPTIONS` pre-flight request for a random endpoint, asking to send credentials, and it succeeded. " +
                            "Make sure that you haven't allowed credentials globally.",
                    "true", result.getResponse().getHeader("Access-Control-Allow-Credentials"));
        }
    }

    @Test
    public void task_3() throws Exception {
        task_2();
        // global settings

        CorsConfiguration configuration = this.cors.getCorsConfiguration
                (new MockHttpServletRequest("GET", "/" + UUID.randomUUID()));

        assertNotNull(
                "Task 3: Make sure that you've added a mapping for all endpoints by calling `addMapping(\"/**\")`'",
                configuration);
        assertEquals(
                "Task 3: Make sure that globally you are only allowing `HEAD`",
                1, configuration.getAllowedMethods().size());
        assertEquals(
                "Task 3: Make sure that globally you are only allowing `HEAD`",
                "HEAD", configuration.getAllowedMethods().get(0));
        assertEquals(
                "Task 3: Make sure that globally you are only allowing the `Authorization` header",
                1, configuration.getAllowedHeaders().size());
        assertEquals(
                "Task 3: Make sure that globally you are only allowing the `Authorization` header",
                "Authorization", configuration.getAllowedHeaders().get(0));
        assertEquals(
                "Task 3: Make sure that globally you are only allowing the `http://localhost:8081` origin",
                1, configuration.getAllowedOrigins().size());
        assertEquals(
                "Task 3: Make sure that globally you are only allowing the `http://localhost:8081` origin",
                "http://localhost:8081", configuration.getAllowedOrigins().get(0));

        MvcResult result = this.mvc.perform(options("/goals")
                .header("Access-Control-Request-Method", "GET")
                .header("Origin", "http://localhost:8081"))
                .andReturn();

        assertEquals(
                "Task 3: Tried to do an `OPTIONS` pre-flight request from `http://localhost:8081` for `GET /goals` failed.",
                200, result.getResponse().getStatus());

        result = this.mvc.perform(options("/goals")
                .header("Access-Control-Request-Method", "GET")
                .header("Origin", "http://localhost:5000"))
                .andReturn();

        assertNotEquals(
                "Task 3: Tried to do an `OPTIONS` pre-flight request from `http://localhost:5000` for `GET /goals` and it succeeded.",
                200, result.getResponse().getStatus());

        result = this.mvc.perform(options("/" + UUID.randomUUID())
                .header("Access-Control-Request-Method", "GET")
                .header("Origin", "http://localhost:8081"))
                .andReturn();

        assertNotEquals(
                "Task 3: Tried to do an `OPTIONS` pre-flight request from `http://localhost:8081` for a random endpoint, and it succeeded.",
                200, result.getResponse().getStatus());
    }

    private <T extends Filter> T getFilter(Class<T> filterClass) {
        List<Filter> filters = this.springSecurityFilterChain.getFilters("/goals");
        for (Filter filter : filters) {
            if (filter.getClass() == filterClass) {
                return (T) filter;
            }
        }

        return null;
    }
}
