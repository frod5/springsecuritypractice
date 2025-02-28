package io.security.springsecuritymaster.security.handler;

import java.io.IOException;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import io.security.springsecuritymaster.security.exception.SecretException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FormAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException exception) throws IOException, ServletException {

		String msg = "";

		if(exception instanceof BadCredentialsException) {
			msg = "Invalid username or password";
		} else if (exception instanceof UsernameNotFoundException) {
			msg = "Invalid username or password";
		} else if (exception instanceof CredentialsExpiredException) {
			msg = "Expired password";
		} else if (exception instanceof SecretException) {
			msg = "Invalid sercet";
		}

		setDefaultFailureUrl("/login?error=true&exception=" + msg);
		super.onAuthenticationFailure(request, response, exception);
	}
}
