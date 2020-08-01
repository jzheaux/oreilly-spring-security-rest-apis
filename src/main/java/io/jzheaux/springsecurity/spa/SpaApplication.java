package io.jzheaux.springsecurity.spa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@SpringBootApplication
public class SpaApplication {
	@Bean
	public TomcatConnectorCustomizer connectorCustomizer() {
		return container -> container.setPort(4000);
	}

	@Configuration
	static class SecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests(authz -> authz
					.anyRequest().permitAll());
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SpaApplication.class, args);
	}
}
