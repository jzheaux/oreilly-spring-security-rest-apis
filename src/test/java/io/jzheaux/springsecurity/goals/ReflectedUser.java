package io.jzheaux.springsecurity.goals;

import javax.persistence.Id;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.UUID;

import static io.jzheaux.springsecurity.goals.ReflectionSupport.getConstructor;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByColumnName;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldByName;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getDeclaredFieldHavingAnnotation;
import static io.jzheaux.springsecurity.goals.ReflectionSupport.getProperty;

public class ReflectedUser {
	static Constructor defaultConstructor;
	static Constructor copyConstructor;
	static Field idColumnField;
	static Field usernameColumnField;
	static Field passwordColumnField;
	static Field enabledColumnField;
	static Field nameColumnField;
	static Field subscriptionColumnField;
	static Field userAuthorityCollectionField;
	static Field userFriendCollectionField;
	static Method grantAuthorityMethod;

	static {
		defaultConstructor = getConstructor(User.class);
		if (defaultConstructor != null) defaultConstructor.setAccessible(true);
		copyConstructor = getConstructor(User.class, User.class);
		idColumnField = getDeclaredFieldHavingAnnotation(User.class, Id.class);
		usernameColumnField = getDeclaredFieldByColumnName(User.class, "username");
		if (usernameColumnField != null) usernameColumnField.setAccessible(true);
		passwordColumnField = getDeclaredFieldByColumnName(User.class, "password");
		if (passwordColumnField != null) passwordColumnField.setAccessible(true);
		enabledColumnField = getDeclaredFieldByColumnName(User.class, "enabled");
		if (enabledColumnField != null) enabledColumnField.setAccessible(true);
		nameColumnField = getDeclaredFieldByColumnName(User.class, "full_name");
		if (nameColumnField != null) nameColumnField.setAccessible(true);
		subscriptionColumnField = getDeclaredFieldByColumnName(User.class, "subscription");
		if (subscriptionColumnField != null) subscriptionColumnField.setAccessible(true);
		userAuthorityCollectionField = getDeclaredFieldByName(User.class, "userAuthorities");
		if (userAuthorityCollectionField != null) userAuthorityCollectionField.setAccessible(true);
		userFriendCollectionField = getDeclaredFieldByName(User.class, "friends");
		try {
			grantAuthorityMethod = User.class.getDeclaredMethod("grantAuthority", String.class);
		} catch (Exception ignored) {
			// user hasn't added this method yet
		}
	}

	User user;

	public static ReflectedUser newInstance() {
		try {
			return new ReflectedUser((User) defaultConstructor.newInstance());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static ReflectedUser copiedInstance(ReflectedUser user) {
		try {
			return new ReflectedUser((User) copyConstructor.newInstance(user.user));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public ReflectedUser(User user) {
		this.user = user;
	}

	UUID getId() {
		return getProperty(this.user, idColumnField);
	}

	String getUsername() {
		return getProperty(this.user, usernameColumnField);
	}

	String getPassword() {
		return getProperty(this.user, passwordColumnField);
	}

	String getFullName() { return getProperty(this.user, nameColumnField); }

	String getSubscription() { return getProperty(this.user, subscriptionColumnField); }

	Collection<UserAuthority> getUserAuthorities() {
		return getProperty(this.user, userAuthorityCollectionField);
	}

	Collection<User> getFriends() { return getProperty(this.user, userFriendCollectionField); }

	void grantAuthority(String authority) {
		try {
			grantAuthorityMethod.invoke(this.user, authority);
		} catch (Exception e) {
			throw new RuntimeException("Failed to call `grantAuthority` on " + this.user, e);
		}
	}
}
