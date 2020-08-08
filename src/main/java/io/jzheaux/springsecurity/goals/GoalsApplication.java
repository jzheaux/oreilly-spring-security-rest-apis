package io.jzheaux.springsecurity.goals;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class GoalsApplication extends WebSecurityConfigurerAdapter {

	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authz -> authz
				.anyRequest().authenticated()
			)
			.httpBasic(withDefaults())
			.cors(withDefaults());
	}

	public static void main(String[] args) {
		SpringApplication.run(GoalsApplication.class, args);
	}

}
