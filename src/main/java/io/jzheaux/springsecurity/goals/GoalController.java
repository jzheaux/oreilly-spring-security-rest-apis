package io.jzheaux.springsecurity.goals;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.transaction.Transactional;
import java.util.Optional;
import java.util.UUID;

@RestController
public class GoalController {
	private final GoalRepository goals;
	private final UserRepository users;

	public GoalController(GoalRepository goals, UserRepository users) {
		this.goals = goals;
		this.users = users;
	}

	@GetMapping("/goals")
	public Iterable<Goal> read() {
		Iterable<Goal> goals = this.goals.findAll();
		for (Goal goal : goals) {
			addName(goal);
		}
		return goals;
	}

	@GetMapping("/goal/{id}")
	public Optional<Goal> read(@PathVariable("id") UUID id) {
		return this.goals.findById(id).map(this::addName);
	}

	@PostMapping("/goal")
	public Goal make(@RequestBody String text) {
		String owner = "user";
		Goal goal = new Goal(text, owner);
		return this.goals.save(goal);
	}

	@PutMapping(path="/goal/{id}/revise")
	@Transactional
	public Optional<Goal> revise(@PathVariable("id") UUID id, @RequestBody String text) {
		this.goals.revise(id, text);
		return read(id);
	}

	@PutMapping("/goal/{id}/complete")
	@Transactional
	public Optional<Goal> complete(@PathVariable("id") UUID id) {
		this.goals.complete(id);
		return read(id);
	}

	@PutMapping("/goal/{id}/share")
	@Transactional
	public Optional<Goal> share(@AuthenticationPrincipal User user, @PathVariable("id") UUID id) {
		Optional<Goal> goal = read(id);
		goal.filter(r -> r.getOwner().equals(user.getUsername()))
				.map(Goal::getText).ifPresent(text -> {
			for (User friend : user.getFriends()) {
				this.goals.save(new Goal(text, friend.getUsername()));
			}
		});
		return goal;
	}

	private Goal addName(Goal goal) {
		String name = this.users.findByUsername(goal.getOwner())
				.map(User::getFullName).orElse("none");
		goal.setText(goal.getText() + ", by " + name);
		return goal;
	}
}
