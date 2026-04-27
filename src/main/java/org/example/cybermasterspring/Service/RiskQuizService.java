package org.example.cybermasterspring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.RiskQuizOption;
import org.example.cybermasterspring.dto.RiskQuizQuestion;
import org.example.cybermasterspring.dto.RiskQuizResult;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class RiskQuizService {

    private final ObjectMapper objectMapper;

    public RiskQuizService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
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
