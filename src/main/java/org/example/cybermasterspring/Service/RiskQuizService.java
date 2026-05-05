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

    // constructor connects the quiz service to jackson and the quiz repository
    public RiskQuizService(ObjectMapper objectMapper,
                           RiskQuizRepository riskQuizRepository) {
        this.objectMapper = objectMapper;
        this.riskQuizRepository = riskQuizRepository;
    }

    // load the quiz questions from the JSON file then turns them into java objects
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

    // calcualtion for the final quiz result from the answers that were submitted by the user
    public RiskQuizResult calculateResult(Map<String, String> answers) {
        List<RiskQuizQuestion> questions = getQuestions();
        Map<String, Integer> categoryScores = new LinkedHashMap<>();
        int totalScore = 0;

        // loop to add up the total score and then also tracks how much risk comes from each category
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

    // return only the questions that should be visible for how the quiz is currently answered
    public List<RiskQuizQuestion> getVisibleQuestions(Map<String, String> answers) {
        return getQuestions().stream()
                .filter(question -> shouldShowQuestion(question, answers))
                .toList();
    }

    // load the latest saved quiz result for one user so it can then be displayed on the dashboard for them
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

    // save the quiz result and recomendations to the db
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

    // build the recommendations so that it is based on the highest scoring risk categories
    public List<String> buildRecommendations(Map<String, Integer> categoryScores) {
        if (categoryScores == null || categoryScores.isEmpty()) {
            return List.of(
                    "Continue reviewing your cyber security controls regularly to keep risk low."
            );
        }

        List<String> recommendations = new ArrayList<>();

        // the top 3 highest scores categories are then used to decide what recommendations to return
        categoryScores.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder()))
                .limit(3)
                .forEach(entry -> recommendations.add(getRecommendationForCategory(entry.getKey())));

        return recommendations.stream()
                .filter(text -> text != null && !text.isBlank())
                .distinct()
                .toList();
    }

    // used to find the answer option object that matches the value that the user had submitted
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

    // check if a question has to be shown based on its show if conditions
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
    // just to match a recommendation to each category
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

    // then convert the recommendations list into json so it can be stored in the db
    private String toJson(List<String> recommendations) {
        try {
            return objectMapper.writeValueAsString(recommendations == null ? List.of() : recommendations);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize quiz recommendations", e);
        }
    }

    // to turn the saved recommendations JSON back to a normal list
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

    // converts the final total score into the risk level thats displayed to the user
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
