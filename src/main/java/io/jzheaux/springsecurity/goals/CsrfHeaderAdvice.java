package io.jzheaux.springsecurity.goals;

import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class CsrfHeaderAdvice {
	@ModelAttribute("csrf")
	public CsrfToken token(CsrfToken token, HttpServletResponse response) {
		response.setHeader(token.getHeaderName(), token.getToken());
		return token;
	}
}
