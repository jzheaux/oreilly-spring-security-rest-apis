package io.jzheaux.springsecurity.goals;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

@Component
public class UserRepositoryJwtAuthenticationConverter
		implements Converter<Jwt, AbstractAuthenticationToken> {

	private final UserRepository users;
	private final JwtGrantedAuthoritiesConverter authoritiesConverter;

	public UserRepositoryJwtAuthenticationConverter(
			UserRepository users, JwtGrantedAuthoritiesConverter authoritiesConverter) {
		this.users = users;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		User user = this.users.findByUsername(jwt.getSubject())
				.orElseThrow(() -> new UsernameNotFoundException("user not found"));
		Collection<GrantedAuthority> authorities = user.getUserAuthorities().stream()
				.map(userAuthority -> new SimpleGrantedAuthority(userAuthority.authority))
				.collect(Collectors.toList());
		authorities.retainAll(this.authoritiesConverter.convert(jwt));
		return new BearerTokenAuthentication(
				new UserOAuth2AuthenticatedPrincipal(user, jwt, authorities),
				new OAuth2AccessToken(BEARER, jwt.getTokenValue(), null, null),
				authorities);
	}

	private static class UserOAuth2AuthenticatedPrincipal extends User
			implements OAuth2AuthenticatedPrincipal {

		private final Jwt jwt;
		private final Collection<GrantedAuthority> authorities;

		public UserOAuth2AuthenticatedPrincipal(User user, Jwt jwt, Collection<GrantedAuthority> authorities) {
			super(user);
			this.jwt = jwt;
			this.authorities = authorities;
		}

		@Override
		public Map<String, Object> getAttributes() {
			return this.jwt.getClaims();
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public String getName() {
			return this.username;
		}
	}
}
