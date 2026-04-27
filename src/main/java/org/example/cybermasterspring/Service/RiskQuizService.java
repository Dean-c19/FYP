package org.example.cybermasterspring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.cybermasterspring.dto.RiskQuizQuestion;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.List;

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
}
