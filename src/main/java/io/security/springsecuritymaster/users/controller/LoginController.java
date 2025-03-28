package io.security.springsecuritymaster.users.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login(@RequestParam(value = "error", required = false) String error,
		@RequestParam(value = "exception", required = false) String exception, Model model) {
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);
		return "login/login";
	}

	@GetMapping("/api/login")
	public String apiLogin() {
		return "rest/login";
	}

	@GetMapping("/sign-up")
	public String signUp() {
		return "login/signUp";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContextHolderStrategy()
			.getContext()
			.getAuthentication();
		if (auth != null) {
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}

		return "redirect:/login";
	}

	@GetMapping("/denied")
	public String denied(@RequestParam(value = "exception", required = false) String exception,
		Model model,
		@AuthenticationPrincipal UserDetails details) {
		model.addAttribute("exception", exception);
		model.addAttribute("username", details.getUsername());
		return "login/denied";
	}
}
