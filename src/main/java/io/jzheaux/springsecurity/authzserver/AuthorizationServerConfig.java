package io.jzheaux.springsecurity.authzserver;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AuthorizationServerConfig {

	@Bean
	@Order(1)
	SecurityFilterChain oauth2Endpoints(HttpSecurity http) throws Exception {
		http
			.addFilterBefore(new ForwardedHeaderFilter(), LogoutFilter.class)
			.cors(Customizer.withDefaults());
		OAuth2AuthorizationServerSecurity.applyDefaultConfiguration(http);
		return http.build();
	}

	@Bean
	WebMvcConfigurer webMvc() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/oauth2/token")
						.allowedOrigins("http://localhost:8081")
						.maxAge(0);
			}
		};
	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("goals-client")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost:8081/bearer.html")
				.scope("goal:read")
				.scope("goal:write")
				.scope("user:read")
				.clientSettings((settings) -> settings.requireUserConsent(true))
				.build();
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	// @formatter:on

	@Bean
	public KeyManager keyManager() {
		return new StaticKeyGeneratingKeyManager();
	}

	// @formatter:off
	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.authorities("app")
				.build();
		UserDetails hasread = User.withDefaultPasswordEncoder()
				.username("hasread")
				.password("password")
				.authorities("app")
				.build();
		UserDetails haswrite = User.withDefaultPasswordEncoder()
				.username("haswrite")
				.password("password")
				.authorities("app")
				.build();
		UserDetails admin = User.withDefaultPasswordEncoder()
				.username("admin")
				.password("password")
				.authorities("app")
				.build();
		return new InMemoryUserDetailsManager(user, hasread, haswrite, admin);
	}
	// @formatter:on

	@Bean
	@Order(2)
	SecurityFilterChain appEndpoints(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.addFilterBefore(new ForwardedHeaderFilter(), LogoutFilter.class)
			.authorizeRequests((authz) -> authz.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults())
			.oauth2ResourceServer((oauth2) -> oauth2
				.jwt(Customizer.withDefaults()));
		return http.build();
		// @formatter:on
	}
}