package io.jzheaux.springsecurity.authzserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuthzApplication {

	@Bean
	public TomcatConnectorCustomizer connectorCustomizer() {
		return container -> container.setPort(8083);
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthzApplication.class, args);
	}

}
