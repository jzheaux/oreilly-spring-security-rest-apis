package io.jzheaux.springsecurity.goals;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.reactive.function.client.WebClient;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@SpringBootTest
public class Module2_Tests {

	@Autowired
	MockMvc mvc;

	@Autowired
	GoalController controller;

	@Autowired
	GoalRepository repository;

	@Autowired(required = false)
	GoalAuthorizer authorizer;

	@Autowired(required = false)
	UserDetailsService userDetailsService;

	@Autowired(required = false)
	CrudRepository<User, UUID> users;

	@Autowired(required = false)
	MethodSecurityInterceptor methodSecurityInterceptor;

	Authentication hasread;
	Authentication haswrite;
	Goal hasreadGoal;
	Goal haswriteGoal;

	@TestConfiguration
	static class WebClientPostProcessor implements DisposableBean {
		MockWebServer userEndpoint = new MockWebServer();

		@Override
		public void destroy() throws Exception {
			this.userEndpoint.shutdown();
		}

		@Autowired(required = false)
		void postProcess(WebClient.Builder web) throws Exception {
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

	@Before
	public void setup() {
		assertNotNull(
				"Module 1: Could not find `UserDetailsService` in the application context; make sure to complete Module 1 " +
						"before starting this one", this.userDetailsService);
		assertNotNull(
				"Module 1: Could not find `UserRepository<User, UUID>` in the application context; make sure to complete Module 1 " +
						"before starting this one", this.users);
		this.hasread = token("hasread");
		this.haswrite = token("haswrite");
		this.hasreadGoal = this.repository.save(new Goal("has read test", "hasread"));
		this.haswriteGoal = this.repository.save(new Goal("has write test", "haswrite"));
	}

	@Test
	public void task_1() throws Exception {
		_task_1();

		Method readMethod = GoalController.class.getDeclaredMethod("read");
		PreAuthorize readPreAuthorize = readMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `GoalController#read()` method.",
				readPreAuthorize);

		AccessDeniedException e = tryAuthorized(this.controller::read, this.hasread);
		if (e != null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#read()` evaluated to `false` when it was " +
					"given a user with a `goal:read` permission. Double check your expression; it " +
					"should look something like `@PreAuthorize(\"hasAuthority('goal:read')\")`");
		}

		e = tryAuthorized(this.controller::read, this.haswrite);
		if (e == null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#read()` evaluated to `true` when it was " +
					"given a user without a `goal:read` permission. Double check your expression; it " +
					"should look something like `@PreAuthorize(\"hasAuthority('goal:read')\")`" );
		}

		MvcResult result = this.mvc.perform(get("/goals")
			.with(httpBasic("hasread", "password")))
			.andReturn();

		assertNotEquals(
				"Task 1: The `/goals` endpoint failed to authenticate with `hasread`/`password`. " +
						"Make sure this username/password is added via your `UserRepository` on startup.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 1: The `/goals` endpoint failed to authorize `hasread`/`password`. " +
						"Make sure this username/password is granted the `goal:read` authority",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 1: The `/goals` endpoint failed with a status code of " +
						result.getResponse().getStatus(),
				200, result.getResponse().getStatus());

		Method makeMethod = GoalController.class.getDeclaredMethod("make", String.class, String.class);
		PreAuthorize makePreAuthorize = makeMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `GoalController#make` method.",
				makePreAuthorize);

		e = tryAuthorized(() -> make("goal", this.haswrite), this.haswrite);
		if (e != null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#make` evaluated to `false` when it was " +
					"given a user with a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`");
		}

		e = tryAuthorized(() -> make("goal", this.hasread), this.hasread);
		if (e == null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#make` evaluated to `true` when it was " +
					"given a user without a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`" );
		}

		readMethod = GoalController.class.getDeclaredMethod("read", UUID.class);
		readPreAuthorize = readMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `GoalController#read(UUID)` method.",
				readPreAuthorize);

		e = tryAuthorized(() -> this.controller.read(this.hasreadGoal.getId()), this.hasread);
		if (e != null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#read(UUID)` evaluated to `false` when it was " +
					"given a user with a `goal:read` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:read')\")`");
		}

		e = tryAuthorized(() -> this.controller.read(this.haswriteGoal.getId()), this.haswrite);
		if (e == null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#read(UUID)` evaluated to `true` when it was " +
					"given a user without a `goal:read` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:read')\")`" );
		}

		Method reviseMethod = GoalController.class.getDeclaredMethod("revise", UUID.class, String.class);
		PreAuthorize revisePreAuthorize = reviseMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `GoalController#revise(UUID, String)` method.",
				revisePreAuthorize);

		e = tryAuthorized(() -> this.controller.revise(this.haswriteGoal.getId(), "new text"), this.haswrite);
		if (e != null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#revise(UUID, String)` evaluated to `false` when it was " +
					"given a user with a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`");
		}

		e = tryAuthorized(() -> this.controller.revise(this.hasreadGoal.getId(), "new text"), this.hasread);
		if (e == null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#revise(UUID, String)` evaluated to `true` when it was " +
					"given a user without a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`" );
		}

		Method completeMethod = GoalController.class.getDeclaredMethod("complete", UUID.class);
		PreAuthorize completePreAuthorize = completeMethod.getAnnotation(PreAuthorize.class);
		assertNotNull(
				"Task 1: Please add the `@PreAuthorize` annotation to the `GoalController#complete(UUID, String)` method.",
				completePreAuthorize);

		e = tryAuthorized(() -> this.controller.complete(this.haswriteGoal.getId()), this.haswrite);
		if (e != null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#complete(UUID, String)` evaluated to `false` when it was " +
					"given a user with a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`");
		}

		e = tryAuthorized(() -> this.controller.complete(this.hasreadGoal.getId()), this.hasread);
		if (e == null) {
			fail("Task 1: Your `@PreAuthorize` annotation for `GoalController#complete(UUID, String)` evaluated to `true` when it was " +
					"given a user without a `goal:write` permission. Double check your expression; it " +
					"should look like `@PreAuthorize(\"hasAuthority('goal:write')\")`" );
		}
	}

	@Test
	public void task_2() throws Exception {
		// use @PostAuthorize
		task_1();
		Method readMethod = GoalController.class.getDeclaredMethod("read", UUID.class);
		PostAuthorize readPostAuthorize = readMethod.getAnnotation(PostAuthorize.class);
		assertNotNull(
				"Task 2: Please add the `@PostAuthorize` annotation to the `GoalController#read(UUID)` method.",
				readPostAuthorize);

		AccessDeniedException e = tryAuthorized(() -> this.controller.read(this.hasreadGoal.getId()), this.hasread);
		if (e != null) {
			fail("Task 2: The `/goal/{id}` endpoint failed to authorize the `hasread` user to read a goal " +
					"that belonged to them. Please double-check your `@PostAuthorize` expression.");
		}

		e = tryAuthorized(() -> this.controller.read(this.haswriteGoal.getId()), this.hasread);
		if (e == null) {
			fail("Task 2: The `/goal/{id}` endpoint authorized the `hasread` user to read a goal " +
					"that didn't belonged to them. Please double-check your `@PostAuthorize` expression.");
		}

		MvcResult result = this.mvc.perform(get("/goal/" + this.hasreadGoal.getId())
				.with(httpBasic("hasread", "password")))
				.andReturn();

		assertNotEquals(
				"Task 2: The `/goal/{id}` endpoint failed to authenticate with `hasread`/`password`. " +
						"Make sure this username/password is added via your `UserRepository` on startup.",
				401, result.getResponse().getStatus());

		assertNotEquals(
				"Task 2: The `/goal/{id}` endpoint failed to authorize `hasread`/`password`. " +
						"Make sure this username/password is granted the `goal:read` authority.",
				403, result.getResponse().getStatus());

		assertEquals(
				"Task 2: The `/goal/{id}` endpoint failed with a status code of " +
						result.getResponse().getStatus(),
				200, result.getResponse().getStatus());

		Method reviseMethod = GoalController.class.getDeclaredMethod("revise", UUID.class, String.class);
		PostAuthorize revisePostAuthorize = reviseMethod.getAnnotation(PostAuthorize.class);
		assertNotNull(
				"Task 2: Please add the `@PostAuthorize` annotation to the `GoalController#revise` method",
				revisePostAuthorize);

		Method completeMethod = GoalController.class.getDeclaredMethod("complete", UUID.class);
		PostAuthorize completePostAuthorize = completeMethod.getAnnotation(PostAuthorize.class);
		assertNotNull(
				"Task 2: Please add the `@PostAuthorize` annotation to the `GoalController#revise` method",
				completePostAuthorize);
	}

	@Test
	public void task_3() throws Exception {
		_task_4();

		Method reviseMethod = GoalRepository.class.getDeclaredMethod("revise", UUID.class, String.class);
		Query reviseQuery = reviseMethod.getAnnotation(Query.class);
		assertNotNull(
				"Task 3: Please restore the `@Query` annotation to the `GoalRepository#revise(UUID, String)` method",
				reviseQuery);

		assertTrue(
				"Task 3: Use the `?#{authentication.name}` expression to change the query and ensure that no update is performed unless the " +
						"goal belongs to the logged-in user",
				reviseQuery.value().contains("?#{authentication"));

		AccessDeniedException e = tryAuthorized(
				() -> this.controller.revise(this.haswriteGoal.getId(), "has write test revised"), this.haswrite);
		if (e != null) {
			fail("Task 3: The `/goal/{id}/revise` endpoint failed to authorize the `haswrite` user to revise a goal " +
					"that belonged to them. Please double-check your `@PostAuthorize` expression");
		} else {
			assertTrue(
					"Task 3: The `/goal/{id}/revise` endpoint failed to revise a goal that belonged to `haswrite`. " +
							"Please double-check your `@Query` expression",
					this.repository.findById(this.haswriteGoal.getId())
							.filter(goal -> goal.getText().contains("has write test revised"))
							.isPresent());
		}

		e = tryAuthorized(
				() -> this.controller.revise(this.hasreadGoal.getId(), "has read test revised"), this.haswrite);
		if (e == null) {
			fail("Task 3: The `/goal/{id}/revise` endpoint authorized the `haswrite` user to revise a goal " +
					"that didn't belonged to them. Please double-check your `@PostAuthorize` expression" );
		} else {
			assertFalse(
					"Task 3: The `/goal/{id}/revise` endpoint allowed `haswrite` to revise a goal that didn't belong to them. " +
							"Please double-check your `@Query` expression",
					this.repository.findById(this.hasreadGoal.getId())
							.filter(goal -> goal.getText().equals("has read test revised"))
							.isPresent());
		}

		Method completeMethod = GoalRepository.class.getDeclaredMethod("complete", UUID.class);
		Query completeQuery = completeMethod.getAnnotation(Query.class);
		assertNotNull(
				"Task 3: Please restore the `@Query` annotation to the `GoalRepository#revise(UUID, String)` method",
				completeQuery);

		assertTrue(
				"Task 3: Use the `?#{authentication.name}` expression to change the query and ensure that no update is performed unless the " +
						"goal belongs to the logged-in user",
				completeQuery.value().contains("?#{authentication"));

		e = tryAuthorized(
				() -> this.controller.complete(this.haswriteGoal.getId()), this.haswrite);
		if (e != null) {
			fail("Task 3: The `/goal/{id}/complete` endpoint failed to authorize the `haswrite` user to revise a goal " +
					"that belonged to them. Please double-check your `@PostAuthorize` expression");
		} else {
			assertTrue(
					"Task 3: The `/goal/{id}/complete` endpoint failed to revise a goal that belonged to `haswrite`. " +
							"Please double-check your `@Query` expression",
					this.repository.findById(this.haswriteGoal.getId())
							.filter(Goal::getCompleted)
							.isPresent());
		}

		e = tryAuthorized(
				() -> this.controller.complete(this.hasreadGoal.getId()), this.haswrite);
		if (e == null) {
			fail("Task 3: The `/goal/{id}/complete` endpoint authorized the `haswrite` user to revise a goal " +
					"that didn't belonged to them. Please double-check your `@PostAuthorize` expression" );
		} else {
			assertFalse(
					"Task 3: The `/goal/{id}/complete` endpoint allowed `haswrite` to revise a goal that didn't belong to them. " +
							"Please double-check your `@Query` expression",
					this.repository.findById(this.hasreadGoal.getId())
							.filter(Goal::getCompleted)
							.isPresent());
		}
	}

	@Test
	public void task_4() throws Exception {
		_task_7();

		UserDetails admin = this.userDetailsService.loadUserByUsername("admin");
		List<String> grantedAuthorities = admin.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toList());
		Optional<User> user = this.users.findById(new ReflectedUser((User) admin).getId());
		List<String> userAuthorities = user
				.map(ReflectedUser::new)
				.map(ReflectedUser::getUserAuthorities)
				.orElse(Collections.emptyList()).stream()
				.map(ReflectedUserAuthority::new)
				.map(ReflectedUserAuthority::getAuthority)
				.collect(Collectors.toList());

		assertTrue(
				"Task 4: Please make sure the admin still has the `ROLE_ADMIN` authority in the database",
				userAuthorities.contains("ROLE_ADMIN"));

		assertTrue(
				"Task 4: After calling your `UserDetailsService`, the admin user is still missing the `goal:read` authority",
				grantedAuthorities.contains("goal:read"));

		assertTrue(
				"Task 4: After calling your `UserDetailsService`, the admin user is still missing the `goal:write` authority",
				grantedAuthorities.contains("goal:write"));

		assertTrue(
				"Task 4: After calling your `UserDetailsService`, the admin user is still missing the `ROLE_ADMIN` authority",
				grantedAuthorities.contains("ROLE_ADMIN"));
	}

	/**
	 * Add the appropriate Spring Boot starter dependency
	 */
	private void _task_1() throws Exception {
		// use @PreAuthorize
		assertNotNull(
				"Task 1: Method Security appears to not be turned on yet. Please make sure that " +
						"you've added `@EnableGlobalMethodSecurity(prePostEnabled = true)` to the application.",
				this.methodSecurityInterceptor);
		DelegatingMethodSecurityMetadataSource delegating = (DelegatingMethodSecurityMetadataSource) this.methodSecurityInterceptor.getSecurityMetadataSource();

		assertTrue(
				"Task 1: Make sure you've configured method security for the `@Pre` and `@PostAuthorize` annotations " +
						"by setting the `prePostEnabled` attribute to `true`",
				delegating.getMethodSecurityMetadataSources().stream()
						.anyMatch(PrePostAnnotationSecurityMetadataSource.class::isInstance));
	}

	private AccessDeniedException tryAuthorized(Runnable runnable, Authentication authentication) {
		try {
			SecurityContextHolder.getContext().setAuthentication(authentication);
			runnable.run();
			return null;
		} catch (AccessDeniedException e) {
			return e;
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	private void _task_4() throws Exception {
		// use post filter
		task_2();

		Method readMethod = GoalController.class.getDeclaredMethod("read");
		PostFilter readPostFilter = readMethod.getAnnotation(PostFilter.class);
		assertNotNull(
				"Task 3: Please add the `@PostFilter` annotation to the `read()` method.",
				readPostFilter);

		SecurityContextHolder.getContext().setAuthentication(this.hasread);
		try {
			Iterable<Goal> goals = this.controller.read();
			assertTrue(
					"Task 3: Calling `GoalController#read()` returned no results. " +
							"Make sure that your filter is keeping records whose owner matches the logged in user.",
					goals.iterator().hasNext());
			for (Goal goal : goals) {
				assertEquals(
						"Task 3: One of the goals returned from RepositoryController#read() " +
								"did not belong to the logged-in user. Make sure that your `@PostFilter` " +
								"annotation is checking that the goal's owner id matches the logged in user's id.",
						"hasread", goal.getOwner());
			}
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	private void _task_6() throws Exception {
		task_3();

		// add custom authorization expression
		try {
			this.userDetailsService.loadUserByUsername("admin");
		} catch (UsernameNotFoundException e) {
			fail("Task 4: No admin user was found. Please double-check that you are adding a user with username `admin` and password `password` to the database");
		}

		Authentication admin = token("admin");
		AccessDeniedException e = tryAuthorized(() -> {
			List<UUID> goals = StreamSupport.stream(this.controller.read().spliterator(), false)
					.map(Goal::getId).collect(Collectors.toList());
			List<UUID> all = StreamSupport.stream(this.repository.findAll().spliterator(), false)
					.map(Goal::getId).collect(Collectors.toList());
			assertEquals(
					"Task 4: The admin user should receive all records back. Please double-check your `@PostFilter` expression that it allows all records if the user has the `ROLE_ADMIN` authority",
					goals, all);
		}, admin);

		assertNull(
				"Task 4: The `/goals` endpoint denied the admin user. Make sure that the admin is granted the `goal:read` authority.",
				e);


		e = tryAuthorized(() -> this.controller.read(this.haswriteGoal.getId()), admin);
		assertNull(
				"Task 4: The `/goals/{id}` GET endpoint failed to authorize the admin user to read a record that doesn't belong to them. " +
						"Please make sure that the admin has the `goal:read` permission and please check your `@PostAuthorize` expression for `GoalController#read(UUID)`",
				e);
	}

	private void _task_7() throws Exception {
		// add custom authorization rule
		_task_6();

		assertNotNull(
				"Task 4: Make sure to add the `GoalAuthorizer` to the application context. " +
						"One way to do this is by adding the `@Component` annotation",
				this.authorizer);

		Authentication admin = token("admin");

		Method authorize = method(GoalAuthorizer.class, "authorize", MethodSecurityExpressionOperations.class);
		assertNotNull(
				"Task 4: Please add an `authorize` method to `GoalAuthorizer` that takes a `MethodSecurityExpressionOperations` as a parameter.",
				authorize);

		MethodSecurityExpressionOperations operations = mock(MethodSecurityExpressionOperations.class);
		when(operations.hasRole("ADMIN")).thenReturn(true);
		when(operations.getAuthentication()).thenReturn(admin);
		when(operations.getReturnObject()).thenReturn(Optional.of(this.hasreadGoal));

		try {
			assertTrue(
					"Task 4: `GoalAuthorizer#authorize` refused to authorize the admin user. Please double-check its logic",
					(boolean) authorize.invoke(this.authorizer, operations));
		} catch (Exception e) {
			fail("Task 4: `GoalAuthorizer#authorize` threw an exception: " + e);
		}

		reset(operations);
		when(operations.hasRole("ADMIN")).thenReturn(false);
		when(operations.getAuthentication()).thenReturn(this.hasread);
		when(operations.getReturnObject()).thenReturn(Optional.of(this.haswriteGoal));

		try {
			assertFalse(
					"Task 4: `GoalAuthorizer#authorize` authorized `hasread` to read a goal owned by `haswrite`. Please double-check its logic",
					(boolean) authorize.invoke(this.authorizer, operations));
		} catch (Exception e) {
			fail("Task 4: `GoalAuthorizer#authorize` threw an exception: " + e);
		}

		PostAuthorize readPostAuthorize = annotation(PostAuthorize.class, "read", UUID.class);
		assertTrue(
				"Task 4: Make sure that you are passing `#root` into the authorizer's `authorize` method",
				readPostAuthorize.value().contains("#root"));

		Method filter = method(GoalAuthorizer.class, "filter", MethodSecurityExpressionOperations.class);
		assertNotNull(
				"Task 4: Please add an `filter` method to `GoalAuthorizer` that takes a `MethodSecurityExpressionOperations` as a parameter.",
				filter);

		reset(operations);
		when(operations.hasRole("ADMIN")).thenReturn(true);
		when(operations.getAuthentication()).thenReturn(admin);
		when(operations.getFilterObject()).thenReturn(this.hasreadGoal);

		try {
			assertTrue(
					"Task 4: `GoalAuthorizer#filter` refused to authorize the admin user. Please double-check its logic",
					(boolean) filter.invoke(this.authorizer, operations));
		} catch (Exception e) {
			fail("Task 4: `GoalAuthorizer#filter` threw an exception: " + e);
		}

		reset(operations);
		when(operations.hasRole("ADMIN")).thenReturn(false);
		when(operations.getAuthentication()).thenReturn(this.hasread);
		when(operations.getFilterObject()).thenReturn(this.haswriteGoal);

		try {
			assertFalse(
					"Task 4: `GoalAuthorizer#filter` authorized `hasread` to read a goal owned by `haswrite`. Please double-check its logic",
					(boolean) filter.invoke(this.authorizer, operations));
		} catch (Exception e) {
			fail("Task 4: `GoalAuthorizer#filter` threw an exception: " + e);
		}

		PostFilter readPostFilter = annotation(PostFilter.class, "read");
		assertTrue(
				"Task 4: Make sure that you are passing `#root` into the authorizer's `authorize` method",
				readPostFilter.value().contains("#root"));

		MvcResult result = this.mvc.perform(get("/goals")
				.with(httpBasic("admin", "password")))
				.andReturn();

		assertEquals(
				"Task 4: The `/goals` endpoint did not allow the admin user, returning the response code of " +
						result.getResponse().getStatus(),
				200, result.getResponse().getStatus());
	}

	Goal make(String text, Authentication token) {
		try {
			ReflectedUser user = new ReflectedUser((User) token.getPrincipal());
			Method make = method(GoalController.class, "make", String.class, String.class);
			return (Goal) make.invoke(this.controller, user.getUsername(), text);
		} catch (Exception e) {
			if (e instanceof InvocationTargetException && e.getCause() instanceof RuntimeException) {
				throw (RuntimeException) e.getCause();
			}
			fail("`GoalController#make` is missing the `username` method parameter. Was this module done before the first module?");
			throw new RuntimeException(e);
		}
	}

	Method method(Class<?> clazz, String method, Class<?>... params) {
		try {
			return clazz.getDeclaredMethod(method, params);
		} catch (Exception e) {
			return null;
		}
	}

	<T extends Annotation> T annotation(Class<T> annotation, String method, Class<?>... params) {
		try {
			Method m = GoalController.class.getDeclaredMethod(method, params);
			return m.getAnnotation(annotation);
		} catch (Exception e) {
			return null;
		}
	}

	Authentication token(String username) {
		UserDetails details = this.userDetailsService.loadUserByUsername(username);
		return new TestingAuthenticationToken(details, details.getPassword(),
				new ArrayList<>(details.getAuthorities()));
	}
}
