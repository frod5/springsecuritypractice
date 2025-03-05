package io.security.springsecuritymaster.users.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.security.springsecuritymaster.domain.dto.AccountDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
public class RestApiController {

	@GetMapping("/user")
	public AccountDto restUser(@AuthenticationPrincipal AccountDto accountDto) {
		return accountDto;
	}

	@GetMapping("/manager")
	public AccountDto restManager(@AuthenticationPrincipal AccountDto accountDto) {
		return accountDto;
	}

	@GetMapping("/admin")
	public AccountDto restAdmin(@AuthenticationPrincipal AccountDto accountDto) {
		return accountDto;
	}

	@GetMapping("/logout")
	public String restLogout(HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContextHolderStrategy()
			.getContext()
			.getAuthentication();

		if (auth != null) {
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}

		return "logout";
	}
}
