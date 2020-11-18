package io.jzheaux.springsecurity.goals;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByColumnName;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByName;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print= MockMvcPrint.NONE)
@SpringBootTest
public class Module5_Tests {

    @Autowired
    MockMvc mvc;


    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri:#{null}}")
    String introspectionUrl;

    @Autowired(required = false)
    OpaqueTokenIntrospector introspector;


    @Autowired(required = false)
    UserDetailsService userDetailsService;

    @Autowired
    GoalController goalController;

    @Autowired
    GoalRepository goalRepository;

    @Autowired
    AuthorizationServer authz;

    @Before
    public void setup() {
        assertNotNull(
                "Module 1: Could not find `UserDetailsService` in the application context; make sure to complete the earlier modules " +
                        "before starting this one", this.userDetailsService);
    }

    @TestConfiguration
    static class WebClientPostProcessor implements DisposableBean {
        static String userBaseUrl;

        MockWebServer userEndpoint = new MockWebServer();

        @Override
        public void destroy() throws Exception {
            this.userEndpoint.shutdown();
        }

        @Autowired(required = false)
        void postProcess(WebClient.Builder web) throws Exception {
            Field field = web.getClass().getDeclaredField("baseUrl");
            field.setAccessible(true);
            userBaseUrl = (String) field.get(web);
            web.baseUrl(this.userEndpoint.url("").toString());
        }

        @Bean
        MockWebServer userEndpoint() {
            this.userEndpoint.setDispatcher(new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest recordedRequest) {
                    MockResponse response = new MockResponse().setResponseCode(200);
                    String path = recordedRequest.getPath();
                    switch(path) {
                        case "/user/user/fullName":
                            return response.setBody("User Userson");
                        case "/user/hasread/fullName":
                            return response.setBody("Has Read");
                        case "/user/haswrite/fullName":
                            return response.setBody("Has Write");
                        case "/user/admin/fullName":
                            return response.setBody("Admin Adminson");
                        default:
                            return response.setResponseCode(404);
                    }
                }
            });
            return this.userEndpoint;
        }
    }

    @TestConfiguration
    static class TestConfig implements DisposableBean, InitializingBean {
        AuthorizationServer server = new AuthorizationServer();

        @Override
        public void afterPropertiesSet() throws Exception {
            this.server.start();
        }

        @Override
        public void destroy() throws Exception {
            this.server.stop();
        }

        @ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")
        @Bean
        JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
            return JwtDecoders.fromOidcIssuerLocation(this.server.issuer());
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
                    this.server.introspectionUri(),
                    properties.getOpaquetoken().getClientId(),
                    properties.getOpaquetoken().getClientSecret());
        }

        @Bean
        AuthorizationServer authz() {
            return this.server;
        }
    }

    @TestConfiguration
    static class OpaqueTokenPostProcessor {
        @Autowired
        AuthorizationServer authz;

        @Autowired(required=false)
        void introspector(OpaqueTokenIntrospector introspector) throws Exception {
            NimbusOpaqueTokenIntrospector nimbus = null;
            if (introspector instanceof NimbusOpaqueTokenIntrospector) {
                nimbus = (NimbusOpaqueTokenIntrospector) introspector;
            } else if (introspector instanceof UserRepositoryOpaqueTokenIntrospector) {
                Field delegate =
                        getDeclaredFieldByType(UserRepositoryOpaqueTokenIntrospector.class, OpaqueTokenIntrospector.class);
                if (delegate == null) {
                    delegate = getDeclaredFieldByType(UserRepositoryOpaqueTokenIntrospector.class, NimbusOpaqueTokenIntrospector.class);
                }
                if (delegate != null) {
                    delegate.setAccessible(true);
                    nimbus = (NimbusOpaqueTokenIntrospector) delegate.get(introspector);
                }
            }

            if (nimbus != null) {
                nimbus.setRequestEntityConverter(
                        defaultRequestEntityConverter(URI.create(this.authz.introspectionUri())));
            }
        }

        private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri) {
            return token -> {
                HttpHeaders headers = requestHeaders();
                MultiValueMap<String, String> body = requestBody(token);
                return new RequestEntity<>(body, headers, HttpMethod.POST, introspectionUri);
            };
        }

        private HttpHeaders requestHeaders() {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
            return headers;
        }

        private MultiValueMap<String, String> requestBody(String token) {
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("token", token);
            return body;
        }
    }

    @Test
    public void task_1() throws Exception {
        _task_1();
        // add application.yml configuration
        assertNotNull(
                "Task 1: Could not find an `OpaqueTokenIntrospector` bean in the application context." +
                "Make sure that you are specifying the correct property in `application.yml`",
                this.introspector);

        String introspectionUrl = "http://idp:8083/oauth2/introspect";
        assertEquals(
                "Task 1: Make sure that the `introspection-uri` property is set to `" + introspectionUrl + "`",
                introspectionUrl, this.introspectionUrl);
    }

    @Test
    public void task_2() throws Exception {
        task_1();
        // customize OpaqueTokenIntrospector

        assertNotNull(
                "Task 2: Please make sure that you've supplied an instance of `UserRepositoryOpaqueTokenIntrospector` to the application context",
                this.introspector instanceof UserRepositoryOpaqueTokenIntrospector);

        String token = this.authz.token("user", "goal:read");
        OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
        assertFalse(
                "Task 2: For a token with a scope of `goal:read`, your custom `OpaqueTokenIntrospector` returned no scopes back",
                principal.getAuthorities().isEmpty());
        assertEquals(
                "Task 2: For a token with a scope of `goal:read`, a `GrantedAuthority` of `goal:read` was not returned. " +
                        "Make sure that you are stripping off the `SCOPE_` prefix in your custom `OpaqueTokenIntrospector`",
                "goal:read", principal.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void task_3() throws Exception {
        _task_3();
        // reconcile with UserRepository using JwtAuthenticationConverter

        String token = this.authz.token(UUID.randomUUID().toString(), "goal:write");
        try {
            this.introspector.introspect(token);
            fail(
                    "Task 6: Create a custom `OpaqueTokenIntrospector` that reconciles the `sub` field in the token response " +
                            "with what's in the `UserRepository`. If the user isn't there, throw a `UsernameNotFoundException`.");
        } catch (UsernameNotFoundException expected) {
            // ignore
        } finally {
            this.authz.revoke(token);
        }
    }

    @Test
    public void task_4() throws Exception {
        _task_8();
        // derive share permission
        String token = this.authz.token("haswrite", "goal:write");
        try {
            OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
            assertTrue(
                    "Task 7: Make so that when a token is granted `goal:write` and the user has a `premium` subscription that the " +
                            "final principal as the `goal:share` authority",
                    principal.getAuthorities().contains(new SimpleGrantedAuthority("goal:share")));
        } finally {
            this.authz.revoke(token);
        }
    }

    private void _task_1() throws Exception {

        String token = this.authz.token("user", "goal:read");
        try {
            MvcResult result = this.mvc.perform(get("/goals")
                    .header("Authorization", "Bearer " + token))
                    .andReturn();
            assertNotEquals(
                    "Task 1: Make sure that you've configured the application to use Bearer token authentication by adding the appropriate " +
                            "oauth2ResourceServer call to the Spring Security DSL in `GoalsApplication`",
                    401, result.getResponse().getStatus());
            // until we add scopes, this will be a 403; after we add scopes, it'll be a 200. But it will never been a 401.
        } finally {
            this.authz.revoke(token);
        }
    }

    private void _task_3() throws Exception {
        _task_5();

        // add subscription property
        Field nameField = getDeclaredFieldByColumnName(User.class, "subscription");
        assertNotNull(
                "Please add a subscription property to the `User` class with a column called `subscription`",
                nameField);

        ReflectedUser user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("haswrite"));
        ReflectedUser copy = ReflectedUser.copiedInstance(user);
        assertEquals(
                "Task 3: Update your copy constructor so that the subscription is also copied",
                user.getSubscription(), copy.getSubscription());

        assertEquals(
                "Task 3: Please give `haswrite` a `premium` subscription.",
                "premium", user.getSubscription());

        // add friends property
        Field friendsField = getDeclaredFieldByName(User.class, "friends");
        assertNotNull(
                "Task 3: Please add a friends property to the `User` class that maps to a `Collection` of other `User`s",
                friendsField);

        user = new ReflectedUser((User) this.userDetailsService.loadUserByUsername("haswrite"));
        copy = ReflectedUser.copiedInstance(user);
        Collection<String> userFriends = user.getFriends().stream()
                .map(u -> new ReflectedUser(u).getUsername())
                .collect(Collectors.toList());
        Collection<String> copyFriends = copy.getFriends().stream()
                .map(u -> new ReflectedUser(u).getUsername())
                .collect(Collectors.toList());
        assertEquals(
                "Task 3: The friends of the original and its copy are different.",
                userFriends,
                copyFriends);

        assertFalse(
                "Task 3: Please add `hasread` to `haswrite`'s list of friends",
                userFriends.isEmpty());
        assertTrue(
                "Task 3: Please add `hasread` to `haswrite`'s list of friends",
                userFriends.contains("hasread"));
    }

    private void _task_5() throws Exception {
        task_2();
        // add share endpoint

        Goal goal = this.goalRepository.save(new Goal("haswrite's latest goal", "haswrite"));
        User haswrite = (User) this.userDetailsService.loadUserByUsername("haswrite");
        TestingAuthenticationToken token = new TestingAuthenticationToken
                (haswrite, haswrite, AuthorityUtils.createAuthorityList("goal:write", "goal:share"));
        MvcResult result = this.mvc.perform(put("/goal/" + goal.getId() + "/share")
                .with(authentication(token))
                .with(csrf()))
                .andReturn();

        assertEquals(
                "Task 5: The `PUT /goal/{id}/share` endpoint failed to authorize a user that is granted the `goal:share` permission.",
                200, result.getResponse().getStatus());
        User hasread = (User) this.userDetailsService.loadUserByUsername("hasread");
        token = new TestingAuthenticationToken
                (hasread, hasread, AuthorityUtils.createAuthorityList("goal:read"));
        SecurityContextHolder.getContext().setAuthentication(token);
        try {
            Collection<String> texts = StreamSupport.stream(this.goalController.read().spliterator(), false)
                    .map(Goal::getText).collect(Collectors.toList());
            assertTrue(
                    "Task 5: Even though `haswrite` shared a `Goal` with `hasread`, `hasread` doesn't have it or its getting filtered out. " +
                            "Make sure that you are sending the correct username to `GoalController#make",
                    texts.contains("haswrite's latest goal"));
        } finally {
            SecurityContextHolder.clearContext();
        }

        goal = this.goalRepository.save(new Goal("user's latest goal", "user"));
        token = new TestingAuthenticationToken
                (haswrite, haswrite, AuthorityUtils.createAuthorityList("goal:write", "goal:share"));
        result = this.mvc.perform(put("/goal/" + goal.getId() + "/share")
                .with(authentication(token))
                .with(csrf()))
                .andReturn();

        assertEquals(
                "Task 5: A user with the `goal:share` authority was able to share a goal that wasn't theirs.",
                403, result.getResponse().getStatus());

        token = new TestingAuthenticationToken
                (hasread, hasread, AuthorityUtils.createAuthorityList("goal:read", "user:read"));
        SecurityContextHolder.getContext().setAuthentication(token);
        try {
            Iterable<Goal> goals = this.goalController.read();
            for (Goal hasReadGoals : goals) {
                assertNotEquals(
                        "Task 5: A user with the `goal:share` authority was able to share a goal that wasn't theirs.",
                        "user's latest goal", hasReadGoals.getText());
            }
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void _task_8() throws Exception {
        task_3();
        // create custom principal
        Goal goal = this.goalRepository.save(new Goal("haswrite's new goal", "haswrite"));
        String token = this.authz.token("haswrite", "goal:write");
        try {
            MvcResult result = this.mvc.perform(put("/goal/" + goal.getId() + "/share")
                    .header("Authorization", "Bearer " + token))
                    .andReturn();

            assertEquals(
                    "Task 5: The `/goal/{id}/share` endpoint failed to authorize a user that is granted the `goal:share` permission.",
                    200, result.getResponse().getStatus());
        } finally {
            this.authz.revoke(token);
        }
    }

}
