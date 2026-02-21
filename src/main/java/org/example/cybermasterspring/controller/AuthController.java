package org.example.cybermasterspring.controller;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.dto.ThreatEvent;
import org.example.cybermasterspring.dto.CveTrendItem;
import org.example.cybermasterspring.service.CyberNewsService;
import org.example.cybermasterspring.service.AbuseIpService;
import org.example.cybermasterspring.service.UserService;
import org.example.cybermasterspring.service.CveTrendService;
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
    

    public AuthController(UserService userService, CyberNewsService cyberNewsService, AbuseIpService abuseIpService, CveTrendService cveTrendService) {
        this.userService = userService;
        this.cyberNewsService = cyberNewsService;
        this.abuseIpService = abuseIpService;
        this.cveTrendService = cveTrendService;
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

    @GetMapping("/api/threat-events")
    @ResponseBody
    public java.util.List<ThreatEvent> threatEvents() {
        return abuseIpService.getThreatEvents();
    }

    @GetMapping("/api/cve/most-discussed")
    @ResponseBody
    public java.util.List<CveTrendItem> mostDiscussedCves() {
        return cveTrendService.getMostDiscussed(6);
    }

}
