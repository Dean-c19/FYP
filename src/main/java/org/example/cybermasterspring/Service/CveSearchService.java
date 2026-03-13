package org.example.cybermasterspring.service;

import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class CveSearchService {

    public List<CveFinding> scan(List<SoftwareItem> items) {
        return Collections.emptyList();
    }
}
