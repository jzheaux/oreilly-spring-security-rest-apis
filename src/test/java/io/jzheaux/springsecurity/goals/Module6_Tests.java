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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static io.jzheaux.springsecurity.goals.ReflectionSupport.annotation;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print= MockMvcPrint.NONE)
@SpringBootTest
public class Module6_Tests {
	@Autowired
	MockMvc mvc;

	@Autowired(required = false)
	WebClient.Builder web;

	@Autowired(required = false)
	UserDetailsService userDetailsService;

	@Autowired(required = false)
	UserService userService;

	@Autowired(required = false)
	OpaqueTokenIntrospector introspector;

	@Autowired
	GoalController goalController;

	@Autowired
	GoalRepository goals;

	@Autowired
	MockWebServer userEndpoint;

	@Autowired
	AuthorizationServer authz;

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
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			return headers;
		}

		private MultiValueMap<String, String> requestBody(String token) {
			MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
			body.add("token", token);
			return body;
		}
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

	@Before
	public void setup() throws Exception {
		assertNotNull(
				"Module 1: Could not find an instance of `UserDetailsService` in the application " +
						"context. Make sure that you've already completed earlier modules before starting " +
						"this one.",
				this.userDetailsService);
	}

	@Test
	public void task_1() throws Exception {
		// @Cross Origin without credentials
		CrossOrigin crossOrigin = annotation(CrossOrigin.class, "read");
		assertNotNull(
				"Task 1: Make sure that there is a `@CrossOrigin` annotation on `GoalController#read`",
				crossOrigin);
		assertNotEquals(
				"Task 1: Since you are using Bearer Token authentication now, `allowCredentials` should be removed",
				"true", crossOrigin.allowCredentials());

		MvcResult result = this.mvc.perform(options("/goals")
				.header("Access-Control-Request-Method", "GET")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Origin", "http://localhost:8081"))
				.andReturn();

		assertNull(
				"Task 1: Did an `OPTIONS` pre-flight request from `http://localhost:8081` for `GET /goals`, and it is allowing credentials;" +
						"this should be shut off now that you are using Bearer Token authentication",
				result.getResponse().getHeader("Access-Control-Allow-Credentials"));
/*
		result = this.mvc.perform(options("/" + UUID.randomUUID())
				.header("Access-Control-Request-Method", "HEAD")
				.header("Access-Control-Allow-Credentials", "true")
				.header("Origin", "http://localhost:8081"))
				.andReturn();

		assertNull(
				"Task 1: Did an `OPTIONS` pre-flight request from `http://localhost:8081` for a random endpoint, and it is allowing credentials;" +
						"this should be shut off now that you are using Bearer Token authentication",
				result.getResponse().getHeader("Access-Control-Allow-Credentials"));*/
	}

	@Test
	public void task_2() throws Exception {
		_task_2();

		// publish web client
		assertNotNull(
				"Task 3: Make sure you are adding an instance of `ServletBearerExchangeFilterFunction` to your " +
						"`WebClient.Builder` definition",
				getFilter(ServletBearerExchangeFilterFunction.class));
	}

	private void _task_2() throws Exception {
		_task_4();
		// add UserService

		assertNotNull(
				"Task 2: Make sure to publish a `@Bean` of type `WebClient.Builder`",
				this.web);

		assertNotNull(
				"Task 2: Make sure to publish your `UserService`",
				this.userService);

		assertEquals(
				"Task 2: The `WebClient` should be set to have a `baseUrl` of `http://localhost:8080`",
				"http://localhost:8080", WebClientPostProcessor.userBaseUrl);

		String name = this.userService.getFullName("user")
				.orElseGet(() -> fail("Task 2: `UserService#getFullName` returned no results for username `user`. " +
						"Make sure that you are calling the `/user/{username}/fullName` endpoint in the implementation"));
		assertEquals(
				"Task 2: `UserService#getFullName` returned an unexpected result for username `user`. " +
						"Make sure that you are calling the `/user/{username}/fullName` endpoint in the implementation",
				"User Userson", name);

		assertTrue(
				"Task 2: It doesn't appear that the `WebClient` is getting called. Make sure that you are " +
						"invoking the `WebClient` to address the `/user/{username}/fullName` endpoint.",
				this.userEndpoint.getRequestCount() > 0);
	}

	private void _task_4() throws Exception {
		task_1();
		// update goal controller

		int count = this.userEndpoint.getRequestCount();
		this.goals.save(new Goal("my last goal", "user"));
		String token = this.authz.token("user", "goal:read user:read");
		Authentication authentication = getAuthentication(token);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		try {
			Iterable<Goal> goals = this.goalController.read();
			assertTrue(
					"Task 4: It appears that `GoalController` is not calling `UserService`. " +
							"Make sure to switch `UserRepository` with `UserService`",
					this.userEndpoint.getRequestCount() > count);
			for (Goal goal : goals) {
				assertTrue(
						"Task 4: The `/goals` endpoint didn't append the user's personal name in the resolution text.",
						goal.getText().endsWith("User Userson"));
			}
		} finally {
			SecurityContextHolder.clearContext();
			this.authz.revoke(token);
		}
	}

	private <T extends ExchangeFilterFunction> T getFilter(Class<T> clazz) throws Exception {
		Field filtersField = this.web.getClass().getDeclaredField("filters");
		filtersField.setAccessible(true);
		List<ExchangeFilterFunction> filters = (List<ExchangeFilterFunction>)
				filtersField.get(this.web);
		if (filters == null) {
			return null;
		}
		for (ExchangeFilterFunction filter : filters) {
			if (filter instanceof ServletBearerExchangeFilterFunction) {
				return (T) filter;
			}
		}
		return null;
	}

	private Authentication getAuthentication(String token) {
		OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
		OAuth2AccessToken credentials = new OAuth2AccessToken(BEARER, token, null, null);
		return new BearerTokenAuthentication(principal, credentials, principal.getAuthorities());
	}
}
