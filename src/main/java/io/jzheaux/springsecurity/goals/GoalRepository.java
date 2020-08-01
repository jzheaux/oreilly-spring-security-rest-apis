package io.jzheaux.springsecurity.goals;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface GoalRepository extends CrudRepository<Goal, UUID> {
	@Modifying
	@Query("UPDATE Goal SET text = :text WHERE id = :id")
	void revise(UUID id, String text);

	@Modifying
	@Query("UPDATE Goal SET completed = 1 WHERE id = :id")
	void complete(UUID id);
}
