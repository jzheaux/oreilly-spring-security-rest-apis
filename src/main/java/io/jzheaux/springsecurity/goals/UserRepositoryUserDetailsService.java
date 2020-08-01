package io.jzheaux.springsecurity.goals;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class UserRepositoryUserDetailsService implements UserDetailsService {
	private final UserRepository users;

	public UserRepositoryUserDetailsService(UserRepository users) {
		this.users = users;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.users.findByUsername(username)
				.map(UserBridge::new)
				.orElseThrow(() -> new UsernameNotFoundException("Couldn't find user"));
	}

	private static class UserBridge extends User implements UserDetails {
		UserBridge(User user) {
			super(user);
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			for (UserAuthority userAuthority : this.userAuthorities) {
				authorities.add(new SimpleGrantedAuthority(userAuthority.authority));
			}
			return authorities;
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}
	}
}
