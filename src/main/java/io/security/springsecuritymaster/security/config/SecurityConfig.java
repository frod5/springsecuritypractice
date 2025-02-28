package io.security.springsecuritymaster.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

	public SecurityConfig(
		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth
				.requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*", "/h2-console/**").permitAll()
				.requestMatchers("/", "/sign-up").permitAll()
				.anyRequest().authenticated()
			)
			.formLogin(form -> form
				.loginPage("/login").permitAll()
				.authenticationDetailsSource(authenticationDetailsSource));

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
