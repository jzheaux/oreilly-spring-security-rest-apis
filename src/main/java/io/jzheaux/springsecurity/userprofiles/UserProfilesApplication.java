package io.jzheaux.springsecurity.userprofiles;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@SpringBootApplication
public class UserProfilesApplication {
	@Bean
	public TomcatConnectorCustomizer connectorCustomizer() {
		return container -> container.setPort(8081);
	}

	@RestController
	static class UserController {
		@GetMapping("/user/{username}/fullName")
		Optional<String> read(@PathVariable("username") String username) {
			switch(username) {
				case "user":
					return Optional.of("User Userson");
				case "hasread":
					return Optional.of("Has Read");
				case "haswrite":
					return Optional.of("Has Write");
				case "admin":
					return Optional.of("Admin Adminson");
				default:
					return Optional.empty();
			}
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(UserProfilesApplication.class, args);
	}
}
