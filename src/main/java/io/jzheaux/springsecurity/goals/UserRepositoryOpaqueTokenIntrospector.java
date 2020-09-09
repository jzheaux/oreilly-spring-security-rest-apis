package io.jzheaux.springsecurity.goals;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class UserRepositoryOpaqueTokenIntrospector
		implements OpaqueTokenIntrospector {

	private final UserRepository users;
	private final OpaqueTokenIntrospector introspector;

	public UserRepositoryOpaqueTokenIntrospector(
			UserRepository users, OpaqueTokenIntrospector introspector) {

		this.users = users;
		this.introspector = introspector;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(token);
		User user = this.users.findByUsername(principal.getName())
				.orElseThrow(() -> new UsernameNotFoundException("user not found"));
		Collection<GrantedAuthority> authorities = user.getUserAuthorities().stream()
				.map(userAuthority -> new SimpleGrantedAuthority(userAuthority.authority))
				.collect(Collectors.toList());
		Collection<String> scope = principal.getAttribute("scope");
		Collection<GrantedAuthority> scopes = scope.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		authorities.retainAll(scopes);

		// add the virtual authority goal:share that's based on whether this
		// authentication can goal:write authority as well as the user has a premium membership

		return new UserOAuth2AuthenticatedPrincipal(user, principal.getAttributes(), authorities);
	}

	private static class UserOAuth2AuthenticatedPrincipal extends User
			implements OAuth2AuthenticatedPrincipal {

		private final Map<String, Object> attributes;
		private final Collection<GrantedAuthority> authorities;

		public UserOAuth2AuthenticatedPrincipal(
				User user, Map<String, Object> attributes, Collection<GrantedAuthority> authorities) {
			super(user);
			this.attributes = attributes;
			this.authorities = authorities;
		}

		@Override
		public Map<String, Object> getAttributes() {
			return this.attributes;
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
