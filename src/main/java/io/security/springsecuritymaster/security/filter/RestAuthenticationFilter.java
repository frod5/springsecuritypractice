package io.security.springsecuritymaster.security.filter;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.security.token.RestAuthenticationToken;
import io.security.springsecuritymaster.security.util.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private final ObjectMapper objectMapper = new ObjectMapper();

	public RestAuthenticationFilter(HttpSecurity http) {
		super(new AntPathRequestMatcher("/api/login","POST"));
		setSecurityContextRepository(getSecurityContextRepository(http));
	}

	private SecurityContextRepository getSecurityContextRepository(HttpSecurity http) {
		SecurityContextRepository repository = http.getSharedObject(SecurityContextRepository.class);

		if (repository == null) {
			repository = new DelegatingSecurityContextRepository(new RequestAttributeSecurityContextRepository(),
				new HttpSessionSecurityContextRepository());
		}

		return repository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException,
		IOException,
		ServletException {

		if(!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
			throw new IllegalArgumentException("Unsupported HTTP method: " + request.getMethod());
		}

		AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
		if(!StringUtils.hasText(accountDto.username()) || !StringUtils.hasText(accountDto.password())) {
			throw new AuthenticationServiceException("Username or password is missing");
		}

		RestAuthenticationToken token = new RestAuthenticationToken(accountDto.username(), accountDto.password());

		return this.getAuthenticationManager().authenticate(token);
	}
}
