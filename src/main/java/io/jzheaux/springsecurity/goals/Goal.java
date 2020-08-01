package io.jzheaux.springsecurity.goals;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.util.UUID;

@Entity
public class Goal {
	@Id
	private UUID id;

	@Column
	private String text;

	@Column
	private String owner;

	@Column(nullable=false)
	private Boolean completed = false;

	public Goal() {
	}

	public Goal(String text, String owner) {
		this.id = UUID.randomUUID();
		this.text = text;
		this.owner = owner;
	}

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

	public String getOwner() {
		return owner;
	}

	public void setOwner(String owner) {
		this.owner = owner;
	}

	public Boolean getCompleted() {
		return completed;
	}

	public void setCompleted(Boolean completed) {
		this.completed = completed;
	}
}
