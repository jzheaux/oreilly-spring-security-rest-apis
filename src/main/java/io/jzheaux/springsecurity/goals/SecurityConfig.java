package io.jzheaux.springsecurity.goals;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig {

	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("user")
						.password("{bcrypt}$2a$10$3njzOWhsz20aimcpMamJhOnX9Pb4Nk3toq8OO0swIy5EPZnb1YyGe")
						.authorities("goal:read")
						.build());
	}
}
