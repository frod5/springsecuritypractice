package io.security.springsecuritymaster.users.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login() {
		return "login/login";
	}

	@GetMapping("/sign-up")
	public String signUp() {
		return "login/signUp";
	}
}
