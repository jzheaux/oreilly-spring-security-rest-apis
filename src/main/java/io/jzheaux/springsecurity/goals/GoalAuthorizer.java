package io.jzheaux.springsecurity.goals;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component("post")
public class GoalAuthorizer {
	public boolean authorize(MethodSecurityExpressionOperations operations) {
		if (operations.hasRole("ADMIN")) {
			return true;
		}

		String name = operations.getAuthentication().getName();
		return ((Optional<Goal>) operations.getReturnObject())
				.map(Goal::getOwner)
				.filter(owner -> owner.equals(name)).isPresent();
	}

	public boolean filter(MethodSecurityExpressionOperations operations) {
		if (operations.hasRole("ADMIN")) {
			return true;
		}

		String name = operations.getAuthentication().getName();
		Goal resolution = (Goal) operations.getFilterObject();
		return resolution.getOwner().equals(name);
	}
}
