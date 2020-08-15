package io.jzheaux.springsecurity.goals;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

@Entity(name="users")
public class User implements Serializable {
	@Id
	UUID id;

	@Column
	String username;

	@Column
	String password;

	@Column
	boolean enabled = true;

	@Column(name="full_name")
	String fullName;

	@Column
	String subscription;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	Collection<User> friends = new ArrayList<>();

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
	Collection<UserAuthority> userAuthorities = new ArrayList<>();

	User() {}

	User(String username, String password) {
		this.id = UUID.randomUUID();
		this.username = username;
		this.password = password;
	}

	User(User user) {
		this.id = user.id;
		this.username = user.username;
		this.password = user.password;
		this.enabled = user.enabled;
		this.fullName = user.fullName;
		this.subscription = user.subscription;
		this.friends = user.friends;
		this.userAuthorities = user.userAuthorities;
	}

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getSubscription() {
		return subscription;
	}

	public void setSubscription(String subscription) {
		this.subscription = subscription;
	}

	public Collection<User> getFriends() {
		return friends;
	}

	public void addFriend(User friend) {
		this.friends.add(friend);
	}

	public Collection<UserAuthority> getUserAuthorities() {
		return userAuthorities;
	}

	public void grantAuthority(String authority) {
		this.userAuthorities.add(new UserAuthority(this, authority));
	}
}
