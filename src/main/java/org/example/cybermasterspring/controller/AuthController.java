package org.example.cybermasterspring.controller;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.dto.ThreatEvent;
import org.example.cybermasterspring.dto.ThreatStats;
import org.example.cybermasterspring.service.CyberNewsService;
import org.example.cybermasterspring.service.AbuseIpService;
import org.example.cybermasterspring.service.UserService;
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

    public AuthController(UserService userService, CyberNewsService cyberNewsService, AbuseIpService abuseIpService) {
        this.userService = userService;
        this.cyberNewsService = cyberNewsService;
        this.abuseIpService = abuseIpService;
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

    @GetMapping("/cybernews/article")
    public String cyberNewsArticle(@org.springframework.web.bind.annotation.RequestParam("url") String url,
                                   Model model) {
        model.addAttribute("article", cyberNewsService.getArticleSummary(url));
        return "cybernews-article";
    }

    @GetMapping("/api/threat-stats")
    @ResponseBody
    public java.util.Map<String, java.util.List<ThreatStats>> threatStats() {
        java.util.Map<String, java.util.List<ThreatStats>> data = new java.util.HashMap<>();
        data.put("topAttackers", java.util.List.of(
                new ThreatStats("United States", 83),
                new ThreatStats("China", 5),
                new ThreatStats("Netherlands", 4),
                new ThreatStats("Singapore", 4),
                new ThreatStats("Romania", 4)
        ));
        data.put("topAttacked", java.util.List.of(
                new ThreatStats("United States", 33),
                new ThreatStats("Switzerland", 17),
                new ThreatStats("India", 17),
                new ThreatStats("Australia", 17),
                new ThreatStats("Canada", 16)
        ));
        data.put("topNetworkVectors", java.util.List.of(
                new ThreatStats("UDP Flood", 81),
                new ThreatStats("TCP Flood", 15),
                new ThreatStats("Low and Slow Attack", 2),
                new ThreatStats("DNS Flood", 1),
                new ThreatStats("IP Flood", 1)
        ));
        data.put("topAppViolations", java.util.List.of(
                new ThreatStats("Access violations", 65),
                new ThreatStats("Injections", 23),
                new ThreatStats("Exploits", 7),
                new ThreatStats("Data theft", 3),
                new ThreatStats("Cross-site scripting", 2)
        ));
        return data;
    }

    @GetMapping("/api/threat-events")
    @ResponseBody
    public java.util.List<ThreatEvent> threatEvents() {
        return abuseIpService.getThreatEvents();
    }

}
