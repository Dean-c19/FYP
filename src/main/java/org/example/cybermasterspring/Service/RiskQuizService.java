package org.example.cybermasterspring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.RiskQuizCondition;
import org.example.cybermasterspring.dto.RiskQuizOption;
import org.example.cybermasterspring.dto.RiskQuizQuestion;
import org.example.cybermasterspring.dto.RiskQuizResult;
import org.example.cybermasterspring.dto.RiskQuizSummary;
import org.example.cybermasterspring.model.RiskQuiz;
import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.RiskQuizRepository;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
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

    public RiskQuizSummary getLatestSummary(String username) {
        return riskQuizRepository.findTopByUserUsernameOrderByCompletedAtDesc(username)
                .map(riskQuiz -> new RiskQuizSummary(
                        riskQuiz.getTotalScore(),
                        riskQuiz.getRiskLevel(),
                        riskQuiz.getCompletedAt(),
                        fromJson(riskQuiz.getRecommendationsJson())
                ))
                .orElse(null);
    }

    public void saveResult(User user, RiskQuizResult result, List<String> recommendations) {
        RiskQuiz riskQuiz = new RiskQuiz();
        riskQuiz.setUser(user);
        riskQuiz.setCompletedAt(LocalDateTime.now());
        riskQuiz.setTotalScore(result.getTotalScore());
        riskQuiz.setRiskLevel(result.getRiskLevel());
        riskQuiz.setQuestionsAnswered(result.getAnswers().size());
        riskQuiz.setRecommendationsJson(toJson(recommendations));
        riskQuizRepository.save(riskQuiz);
    }

    public List<String> buildRecommendations(Map<String, Integer> categoryScores) {
        if (categoryScores == null || categoryScores.isEmpty()) {
            return List.of(
                    "Continue reviewing your cyber security controls regularly to keep risk low."
            );
        }

        List<String> recommendations = new ArrayList<>();

        categoryScores.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder()))
                .limit(3)
                .forEach(entry -> recommendations.add(getRecommendationForCategory(entry.getKey())));

        return recommendations.stream()
                .filter(text -> text != null && !text.isBlank())
                .distinct()
                .toList();
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

    private String getRecommendationForCategory(String category) {
        return switch (category) {
            case "Access Control" -> "Strengthen access controls by enabling multi-factor authentication for all accounts and tightening administrator protections.";
            case "Patch Management" -> "Improve patch management by applying security updates on a shorter fixed cycle and removing unsupported software.";
            case "Data Protection" -> "Protect sensitive business data with strong encryption and stricter access restrictions for the people who need it.";
            case "Endpoint Security" -> "Reduce endpoint risk by limiting access to managed devices and enforcing stronger device security controls.";
            case "Backup & Recovery" -> "Improve resilience by testing backups regularly and maintaining offline or immutable backup copies.";
            case "Network Exposure" -> "Reduce network exposure by requiring secure remote access methods such as VPNs and reviewing externally accessible services.";
            case "User Awareness" -> "Support safer day-to-day behaviour with regular cyber security awareness training and clear internal security practices.";
            default -> "Review the highest-scoring risk areas and prioritise practical improvements to reduce business cyber exposure.";
        };
    }

    private String toJson(List<String> recommendations) {
        try {
            return objectMapper.writeValueAsString(recommendations == null ? List.of() : recommendations);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize quiz recommendations", e);
        }
    }

    private List<String> fromJson(String recommendationsJson) {
        try {
            return objectMapper.readValue(
                    recommendationsJson == null || recommendationsJson.isBlank() ? "[]" : recommendationsJson,
                    new TypeReference<List<String>>() {
                    }
            );
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize quiz recommendations", e);
        }
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
