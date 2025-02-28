package io.security.springsecuritymaster.security.handler;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private final RequestCache requestCache = new HttpSessionRequestCache();
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		setDefaultTargetUrl("/");
		SavedRequest saveRequest = requestCache.getRequest(request, response);

		if (saveRequest != null) {
			redirectStrategy.sendRedirect(request, response, saveRequest.getRedirectUrl());
			return;
		}

		redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
	}
}
