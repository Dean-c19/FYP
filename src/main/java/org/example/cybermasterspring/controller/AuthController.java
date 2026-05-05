package org.example.cybermasterspring.controller;

import org.example.cybermasterspring.dto.UserRegistrationDto;
import org.example.cybermasterspring.dto.ThreatEvent;
import org.example.cybermasterspring.dto.CveTrendItem;
import org.example.cybermasterspring.dto.SoftwareItem;
import org.example.cybermasterspring.dto.CveFinding;
import org.example.cybermasterspring.dto.RiskQuizQuestion;
import org.example.cybermasterspring.dto.RiskQuizResult;
import org.example.cybermasterspring.dto.RiskQuizSummary;
import org.example.cybermasterspring.dto.ScanReport;
import org.example.cybermasterspring.dto.ScanHistoryItem;
import org.example.cybermasterspring.service.CyberNewsService;
import org.example.cybermasterspring.service.AbuseIpService;
import org.example.cybermasterspring.service.UserService;
import org.example.cybermasterspring.service.CveTrendService;
import org.example.cybermasterspring.service.CveSearchService;
import org.example.cybermasterspring.service.EmailAlertService;
import org.example.cybermasterspring.service.RiskQuizService;
import org.example.cybermasterspring.service.ScanReportService;
import org.example.cybermasterspring.repository.UserRepository;
import org.example.cybermasterspring.service.VulnerabilityScanService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Controller
public class AuthController {

    private final UserService userService;
    private final CyberNewsService cyberNewsService;
    private final AbuseIpService abuseIpService;
    private final CveTrendService cveTrendService;
    private final CveSearchService cveSearchService;
    private final ScanReportService scanReportService;
    private final VulnerabilityScanService vulnerabilityScanService;
    private final EmailAlertService emailAlertService;
    private final UserRepository userRepository;
    private final RiskQuizService riskQuizService;

    // this controller brings together the main user facing features and hands work off to the right servics
    public AuthController(UserService userService,
                          CyberNewsService cyberNewsService,
                          AbuseIpService abuseIpService,
                          CveTrendService cveTrendService,
                          CveSearchService cveSearchService,
                          ScanReportService scanReportService,
                          VulnerabilityScanService vulnerabilityScanService,
                          EmailAlertService emailAlertService,
                          UserRepository userRepository,
                          RiskQuizService riskQuizService) {
        this.userService = userService;
        this.cyberNewsService = cyberNewsService;
        this.abuseIpService = abuseIpService;
        this.cveTrendService = cveTrendService;
        this.cveSearchService = cveSearchService;
        this.scanReportService = scanReportService;
        this.vulnerabilityScanService = vulnerabilityScanService;
        this.emailAlertService = emailAlertService;
        this.userRepository = userRepository;
        this.riskQuizService = riskQuizService;
    }

    // show the login page
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    // show the registration form and then prepares an empty user object for the form fields
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new UserRegistrationDto());
        return "register";
    }

    // here handles the registration form submission ans then sends the data to the user service class to create the account
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

    // loads the dashboard and also tells the page if a user that is logged in has the admin role
    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        boolean isAdmin = authentication != null
                && authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
        model.addAttribute("isAdmin", isAdmin);
        return "dashboard";
    }

    // shows the live threats page where the frontend later requests the map data from the api endpoint
    @GetMapping("/live-global-threats")
    public String liveGlobalThreats() {
        return "live-global-threats";
    }

    // this loads the cyber news page and gives it the latest rss based news items from the service
    @GetMapping("/cybernews")
    public String cyberNews(Model model) {
        model.addAttribute("cyberNewsItems", cyberNewsService.getLatest(10));
        return "cybernews";
    }

    //  shows the software vulnerability scanner page
    @GetMapping("/software-vulnerability-scanner")
    public String softwareVulnerabilityScanner() {
        return "software-vulnerability-scanner";
    }

    // load the business risk quiz page with the quiz questions and an empty answer map
    @GetMapping("/risk-quiz")
    public String riskQuiz(Model model) {
        Map<String, String> answers = new LinkedHashMap<>();
        List<RiskQuizQuestion> questions = riskQuizService.getQuestions();
        model.addAttribute("quizQuestions", questions);
        model.addAttribute("quizAnswers", answers);
        return "risk-quiz";
    }

    // here i process the quiz answers, calculate the result, build the recomendations and then saves the result for the logged in user
    @PostMapping("/risk-quiz/submit")
    public String submitRiskQuiz(@RequestParam Map<String, String> submittedAnswers,
                                 Authentication authentication,
                                 Model model) {
        Map<String, String> answers = new LinkedHashMap<>(submittedAnswers);
        answers.remove("_csrf");
        List<RiskQuizQuestion> questions = riskQuizService.getVisibleQuestions(answers);
        RiskQuizResult result = riskQuizService.calculateResult(answers);
        List<String> recommendations = riskQuizService.buildRecommendations(result.getCategoryScores());
        if (authentication != null && authentication.isAuthenticated()) {
            userRepository.findByUsername(authentication.getName()).ifPresent(user -> riskQuizService.saveResult(user, result, recommendations));
        }
        model.addAttribute("quizQuestions", questions);
        model.addAttribute("quizAnswers", answers);
        model.addAttribute("quizResult", result);
        model.addAttribute("quizRecommendations", recommendations);
        return "risk-quiz-results";
    }

    //  processe the scanner form, runs the cve search, builds the report, saves the scan and then sends an alert if any high severity issues were found
    @PostMapping("/software-vulnerability-scanner")
    public String submitSoftwareVulnerabilityScanner(
            @RequestParam("softwareList") String softwareList,
            @RequestParam(value = "exactOnly", required = false) String exactOnly,
            Authentication authentication,
            Model model) {
        java.util.List<SoftwareItem> parsedItems = parseSoftwareList(softwareList);
        boolean exactMatchOnly = "on".equalsIgnoreCase(exactOnly);
        java.util.List<CveFinding> findings = cveSearchService.scan(parsedItems, exactMatchOnly);
        ScanReport report = scanReportService.buildReport(parsedItems, findings);
        if (authentication != null && authentication.isAuthenticated()) {
            vulnerabilityScanService.saveScan(authentication.getName(), softwareList, exactMatchOnly, findings, report);
            // if the report has any high severity cves then an email is sent warning the user
            if (report.getHighSeverity() > 0) {
                userRepository.findByUsername(authentication.getName()).ifPresent(user -> {
                    String softwareName = parsedItems.isEmpty() ? "" : parsedItems.get(0).getName();
                    String softwareVersion = parsedItems.isEmpty() ? "" : parsedItems.get(0).getVersion();
                    try {
                        emailAlertService.sendHighRiskScanAlert(
                                user.getEmail(),
                                softwareName,
                                softwareVersion,
                                report
                        );
                    } catch (RuntimeException ignored) {
                    }
                });
            }
        }
        model.addAttribute("submitted", true);
        model.addAttribute("softwareList", softwareList);
        model.addAttribute("parsedItems", parsedItems);
        model.addAttribute("findings", findings);
        model.addAttribute("report", report);
        model.addAttribute("exactOnly", exactMatchOnly);
        return "software-vulnerability-scanner";
    }

    // this turns the raw textarea input into software name and version pairs that the scanner service can then work with
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
            if (trimmed.contains("|") && trimmed.contains(":")) {
                String[] vendorSplit = trimmed.split("\\|", 2);
                String[] versionSplit = vendorSplit[1].split(":", 2);
                String vendor = vendorSplit[0].trim();
                String product = versionSplit[0].trim();
                String version = versionSplit.length > 1 ? versionSplit[1].trim() : "";
                if (!vendor.isEmpty() && !product.isEmpty() && !version.isEmpty()) {
                    items.add(new SoftwareItem(vendor + " " + product, version));
                }
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

    // loads the summary view for one news article
    @GetMapping("/cybernews/article")
    public String cyberNewsArticle(@org.springframework.web.bind.annotation.RequestParam("url") String url,
                                   Model model) {
        model.addAttribute("article", cyberNewsService.getArticleSummary(url));
        return "cybernews-article";
    }

    // api endpoint to return processed threat map events for the frontend map
    @GetMapping("/api/threat-events")
    @ResponseBody
    public java.util.List<ThreatEvent> threatEvents() {
        return abuseIpService.getThreatEvents();
    }

    // api endpoint returns the recent cve items shown in the dashboard area
    @GetMapping("/api/cve/recent")
    @ResponseBody
    public java.util.List<CveTrendItem> mostDiscussedCves() {
        return cveTrendService.getRecentlyPublished(6);
    }

    // this api endpoint returns saved scan history for the logged in user only
    @GetMapping("/api/scans/history")
    @ResponseBody
    public java.util.List<ScanHistoryItem> scanHistory(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return java.util.List.of();
        }
        return vulnerabilityScanService.getUserScanHistory(authentication.getName());
    }

    // api endpoint that returns the latest saved business risk result for the logged in user
    @GetMapping("/api/risk-quiz/latest")
    @ResponseBody
    public RiskQuizSummary latestRiskQuiz(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        return riskQuizService.getLatestSummary(authentication.getName());
    }

}
