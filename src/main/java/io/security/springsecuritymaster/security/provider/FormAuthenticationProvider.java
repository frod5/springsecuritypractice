package io.security.springsecuritymaster.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.security.springsecuritymaster.security.details.FormAuthenticationDetails;
import io.security.springsecuritymaster.security.exception.SecretException;
import io.security.springsecuritymaster.security.service.UserDetailService;

@Component("authenticationProvider")
public class FormAuthenticationProvider implements AuthenticationProvider {

	private final UserDetailService userDetailService;
	private final PasswordEncoder passwordEncoder;

	public FormAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailService userDetailService) {
		this.passwordEncoder = passwordEncoder;
		this.userDetailService = userDetailService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();

		UserDetails userDetails = userDetailService.loadUserByUsername(username);

		if (!passwordEncoder.matches(password, userDetails.getPassword())) {
			throw new BadCredentialsException("Invalid password");
		}

		String secretKey = ((FormAuthenticationDetails)authentication.getDetails()).getSecretKey();

		if(!"secret".equals(secretKey)) {
			throw new SecretException("Invalid secret");
		}

		return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}
