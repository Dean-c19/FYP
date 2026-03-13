package org.example.cybermasterspring.controller;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.dto.ThreatEvent;
import org.example.cybermasterspring.dto.CveTrendItem;
import org.example.cybermasterspring.dto.CveDetail;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.service.CyberNewsService;
import org.example.cybermasterspring.service.AbuseIpService;
import org.example.cybermasterspring.service.UserService;
import org.example.cybermasterspring.service.CveTrendService;
import org.example.cybermasterspring.service.CveSearchService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class AuthController {

    private final UserService userService;
    private final CyberNewsService cyberNewsService;
    private final AbuseIpService abuseIpService;
    private final CveTrendService cveTrendService;
    private final CveSearchService cveSearchService;
    

    public AuthController(UserService userService, CyberNewsService cyberNewsService, AbuseIpService abuseIpService, CveTrendService cveTrendService, CveSearchService cveSearchService) {
        this.userService = userService;
        this.cyberNewsService = cyberNewsService;
        this.abuseIpService = abuseIpService;
        this.cveTrendService = cveTrendService;
        this.cveSearchService = cveSearchService;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new UserRegistrationDto());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") @Valid UserRegistrationDto userDto,
                               BindingResult result,
                               Model model) {
        if (result.hasErrors()) {
            return "register";
        }

        try {
            userService.registerNewUser(userDto);
        } catch (RuntimeException e) {
            model.addAttribute("registrationError", e.getMessage());
            return "register";
        }

        return "redirect:/login?registered";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        boolean isAdmin = authentication != null
                && authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
        model.addAttribute("isAdmin", isAdmin);
        return "dashboard";
    }

    @GetMapping("/live-global-threats")
    public String liveGlobalThreats() {
        return "live-global-threats";
    }

    @GetMapping("/cybernews")
    public String cyberNews(Model model) {
        model.addAttribute("cyberNewsItems", cyberNewsService.getLatest(10));
        return "cybernews";
    }

    @GetMapping("/software-vulnerability-scanner")
    public String softwareVulnerabilityScanner() {
        return "software-vulnerability-scanner";
    }

    @PostMapping("/software-vulnerability-scanner")
    public String submitSoftwareVulnerabilityScanner(
            @org.springframework.web.bind.annotation.RequestParam("softwareList") String softwareList,
            Model model) {
        java.util.List<SoftwareItem> parsedItems = parseSoftwareList(softwareList);
        java.util.List<CveFinding> findings = cveSearchService.scan(parsedItems);
        model.addAttribute("submitted", true);
        model.addAttribute("softwareList", softwareList);
        model.addAttribute("parsedItems", parsedItems);
        model.addAttribute("findings", findings);
        return "software-vulnerability-scanner";
    }

    private java.util.List<SoftwareItem> parseSoftwareList(String softwareList) {
        java.util.List<SoftwareItem> items = new java.util.ArrayList<>();
        if (softwareList == null || softwareList.isBlank()) {
            return items;
        }
        String[] lines = softwareList.split("\\r?\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int colon = trimmed.indexOf(':');
            if (colon <= 0 || colon == trimmed.length() - 1) {
                continue;
            }
            String name = trimmed.substring(0, colon).trim();
            String version = trimmed.substring(colon + 1).trim();
            if (name.isEmpty() || version.isEmpty()) {
                continue;
            }
            items.add(new SoftwareItem(name, version));
        }
        return items;
    }

    @GetMapping("/cybernews/article")
    public String cyberNewsArticle(@org.springframework.web.bind.annotation.RequestParam("url") String url,
                                   Model model) {
        model.addAttribute("article", cyberNewsService.getArticleSummary(url));
        return "cybernews-article";
    }

    @GetMapping("/api/threat-events")
    @ResponseBody
    public java.util.List<ThreatEvent> threatEvents() {
        return abuseIpService.getThreatEvents();
    }

    @GetMapping("/api/cve/recent")
    @ResponseBody
    public java.util.List<CveTrendItem> mostDiscussedCves() {
        return cveTrendService.getRecentlyPublished(6);
    }

    @GetMapping("/api/cve/details")
    @ResponseBody
    public CveDetail cveDetails(@org.springframework.web.bind.annotation.RequestParam("cve") String cve) {
        return cveTrendService.getCveDetail(cve);
    }

}
