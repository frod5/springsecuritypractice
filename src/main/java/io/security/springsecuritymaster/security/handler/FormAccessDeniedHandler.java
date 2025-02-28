package io.security.springsecuritymaster.security.handler;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class FormAccessDeniedHandler implements AccessDeniedHandler {

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private final String errorpage;

	public FormAccessDeniedHandler(String errorpage) {
		this.errorpage = errorpage;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
		AccessDeniedException accessDeniedException) throws IOException, ServletException {
		redirectStrategy.sendRedirect(request, response, errorpage + "?exception="  +accessDeniedException.getMessage());
	}
}
