package io.jzheaux.springsecurity.goals;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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

	@Bean
	WebMvcConfigurer webMvcConfigurer() {
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**")
						.allowedOrigins("http://localhost:4000")
						.allowedMethods("HEAD")
						.allowedHeaders("Authorization");
			}
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(GoalsApplication.class, args);
	}

}
