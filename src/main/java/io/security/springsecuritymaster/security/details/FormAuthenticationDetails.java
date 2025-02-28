package io.security.springsecuritymaster.security.details;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import jakarta.servlet.http.HttpServletRequest;

public class FormAuthenticationDetails extends WebAuthenticationDetails {

	private String secretKey;

	public FormAuthenticationDetails(HttpServletRequest request) {
		super(request);
		secretKey = request.getParameter("secret_key");
	}

	public String getSecretKey() {
		return secretKey;
	}
}
