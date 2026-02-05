package com.example.ecommerce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration for the E-Commerce Application.
 * 
 * WARNING: This configuration is intentionally permissive for demo purposes.
 * In a real application, you would implement proper authentication and
 * authorization.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/h2-console/**").permitAll()
                .anyRequest().permitAll()
                .and()
                .headers().frameOptions().disable(); // For H2 console

        return http.build();
    }
}
