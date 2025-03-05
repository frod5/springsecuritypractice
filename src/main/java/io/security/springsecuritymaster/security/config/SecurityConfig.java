package io.security.springsecuritymaster.security.config;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.security.filter.RestAuthenticationFilter;
import io.security.springsecuritymaster.security.handler.FormAccessDeniedHandler;
import io.security.springsecuritymaster.security.handler.FormAuthenticationSuccessHandler;
import io.security.springsecuritymaster.security.provider.RestAuthenticationProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
	private final AuthenticationSuccessHandler successHandler;
	private final AuthenticationFailureHandler failureHandler;
	private final UserDetailsService userDetailsService;

	public SecurityConfig(
		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource,
		AuthenticationSuccessHandler successHandler, AuthenticationFailureHandler failureHandler,
		UserDetailsService userDetailsService) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		this.successHandler = successHandler;
		this.failureHandler = failureHandler;
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth
				.requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*", "/h2-console/**").permitAll()
				.requestMatchers("/", "/sign-up", "/login*").permitAll()
				.requestMatchers("/user").hasAuthority("ROLE_USER")
				.requestMatchers("/manager").hasAuthority("ROLE_MANAGER")
				.requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
				.anyRequest().authenticated()
			)
			.formLogin(form -> form
				.loginPage("/login").permitAll()
				.authenticationDetailsSource(authenticationDetailsSource)
				.successHandler(successHandler)
				.failureHandler(failureHandler))
			.exceptionHandling(exception -> exception
				.accessDeniedHandler(new FormAccessDeniedHandler("/denied")));

		return http.build();
	}

	@Bean
	@Order(1)
	public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {

		AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
		builder.authenticationProvider(restAuthenticationProvider());
		AuthenticationManager manager = builder.build();

		http.securityMatcher("/api/**")
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*", "/h2-console/**")
				.permitAll()
				.anyRequest()
				.permitAll()
			).csrf(AbstractHttpConfigurer::disable)
			.addFilterBefore(restAuthenticationFilter(manager), UsernamePasswordAuthenticationFilter.class)
			.authenticationManager(manager);

		return http.build();
	}

	private AuthenticationProvider restAuthenticationProvider() {
		return new RestAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	private RestAuthenticationFilter restAuthenticationFilter(AuthenticationManager manager) {
		RestAuthenticationFilter filter = new RestAuthenticationFilter();
		filter.setAuthenticationManager(manager);

		// success
		filter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication authentication) throws IOException, ServletException {
				ObjectMapper mapper = new ObjectMapper();
				response.setStatus(HttpStatus.OK.value());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);

				AccountDto accountDto = new AccountDto(null, authentication.getPrincipal().toString(), null, 0, null);

				mapper.writeValue(response.getWriter(), accountDto);

				clearAuthenticationAttributes(request);
			}

			private void clearAuthenticationAttributes(HttpServletRequest request) {
				HttpSession session = request.getSession(false);
				if (session == null) { return;}
				session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
			}

		});

		//fail
		filter.setAuthenticationFailureHandler(new AuthenticationFailureHandler() {
			@Override
			public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) throws IOException, ServletException {
				ObjectMapper mapper = new ObjectMapper();
				response.setStatus(HttpStatus.UNAUTHORIZED.value());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);

				if(exception instanceof BadCredentialsException) {
					mapper.writeValue(response.getWriter(), "Invalid username or password");
					return;
				}

				mapper.writeValue(response.getWriter(), "authentication failed");

			}
		});

		return filter;
	}



	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
