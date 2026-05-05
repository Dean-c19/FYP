package org.example.cybermasterspring.config;

import org.example.cybermasterspring.model.User;
import org.example.cybermasterspring.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.time.LocalDateTime;

@Configuration
public class SecurityConfig {

    private final UserRepository userRepository;
    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // loads a user from the db and converts it into the spring security format thats used during the login
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            // the enabled value is also mapped here so disabled users are blocked from logging in
            UserDetails userDetails = org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password(user.getPassword())
                    .roles(user.getRole().replace("ROLE_", ""))
                    .disabled(!user.isEnabled())
                    .build();

            return userDetails;
        };
    }

    // this creates the password encoder used to hash and also verify passwords with bcrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // tells spring security to use the user lookup and password checking for when a user logs in
    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    // shows which routes are public and what needs admin access
    // also how login and logout works
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   DaoAuthenticationProvider authProvider,
                                                   AuthenticationSuccessHandler successHandler) throws Exception {

        http.authenticationProvider(authProvider);

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .successHandler(successHandler)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    // after a succesful login this runs so that the last log in time is updated before sending them to the dashboard
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(UserRepository userRepository) {
        return (request, response, authentication) -> {
            String username = authentication.getName();
            userRepository.findByUsername(username).ifPresent(user -> {
                user.setLastLoginAt(LocalDateTime.now());
                userRepository.save(user);
            });
            response.sendRedirect("/dashboard");
        };
    }
}
