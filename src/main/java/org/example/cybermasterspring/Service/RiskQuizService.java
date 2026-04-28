package org.example.cybermasterspring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.RiskQuizCondition;
import org.example.cybermasterspring.dto.RiskQuizOption;
import org.example.cybermasterspring.dto.RiskQuizQuestion;
import org.example.cybermasterspring.dto.RiskQuizResult;
import org.example.cybermasterspring.model.RiskQuiz;
import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.RiskQuizRepository;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class RiskQuizService {

    private final ObjectMapper objectMapper;
    private final RiskQuizRepository riskQuizRepository;

    public RiskQuizService(ObjectMapper objectMapper,
                           RiskQuizRepository riskQuizRepository) {
        this.objectMapper = objectMapper;
        this.riskQuizRepository = riskQuizRepository;
    }

    public List<RiskQuizQuestion> getQuestions() {
        try {
            ClassPathResource resource = new ClassPathResource("risk-quiz-questions.json");
            try (InputStream inputStream = resource.getInputStream()) {
                return objectMapper.readValue(inputStream, new TypeReference<List<RiskQuizQuestion>>() {
                });
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load risk quiz questions", e);
        }
    }

    public RiskQuizResult calculateResult(Map<String, String> answers) {
        List<RiskQuizQuestion> questions = getQuestions();
        Map<String, Integer> categoryScores = new LinkedHashMap<>();
        int totalScore = 0;

        for (RiskQuizQuestion question : questions) {
            String selectedValue = answers.get(question.getId());
            if (selectedValue == null || selectedValue.isBlank()) {
                continue;
            }
            RiskQuizOption selectedOption = findSelectedOption(question, selectedValue);
            if (selectedOption == null) {
                continue;
            }
            totalScore += selectedOption.getScore();
            categoryScores.merge(question.getCategory(), selectedOption.getScore(), Integer::sum);
        }

        return new RiskQuizResult(
                totalScore,
                determineRiskLevel(totalScore),
                categoryScores,
                new LinkedHashMap<>(answers)
        );
    }

    public List<RiskQuizQuestion> getVisibleQuestions(Map<String, String> answers) {
        return getQuestions().stream()
                .filter(question -> shouldShowQuestion(question, answers))
                .toList();
    }

    public void saveResult(User user, RiskQuizResult result) {
        RiskQuiz riskQuiz = new RiskQuiz();
        riskQuiz.setUser(user);
        riskQuiz.setCompletedAt(LocalDateTime.now());
        riskQuiz.setTotalScore(result.getTotalScore());
        riskQuiz.setRiskLevel(result.getRiskLevel());
        riskQuiz.setQuestionsAnswered(result.getAnswers().size());
        riskQuizRepository.save(riskQuiz);
    }

    private RiskQuizOption findSelectedOption(RiskQuizQuestion question, String selectedValue) {
        if (question.getOptions() == null) {
            return null;
        }
        for (RiskQuizOption option : question.getOptions()) {
            if (selectedValue.equals(option.getValue())) {
                return option;
            }
        }
        return null;
    }

    private boolean shouldShowQuestion(RiskQuizQuestion question, Map<String, String> answers) {
        if (question.getShowIf() == null || question.getShowIf().isEmpty()) {
            return true;
        }
        for (RiskQuizCondition condition : question.getShowIf()) {
            String actualAnswer = answers.get(condition.getQuestionId());
            if (actualAnswer == null || !actualAnswer.equals(condition.getEquals())) {
                return false;
            }
        }
        return true;
    }

    private String determineRiskLevel(int totalScore) {
        if (totalScore >= 51) {
            return "Critical";
        }
        if (totalScore >= 31) {
            return "High";
        }
        if (totalScore >= 16) {
            return "Moderate";
        }
        return "Low";
    }
}
