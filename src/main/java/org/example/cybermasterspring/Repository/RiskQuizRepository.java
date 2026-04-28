package org.example.cybermasterspring.repository;

import org.example.cybermasterspring.model.RiskQuiz;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RiskQuizRepository extends JpaRepository<RiskQuiz, Long> {
    Optional<RiskQuiz> findTopByUserUsernameOrderByCompletedAtDesc(String username);
}
