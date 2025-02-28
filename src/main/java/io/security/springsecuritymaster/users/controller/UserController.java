package io.security.springsecuritymaster.users.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.users.service.UserService;

@Controller
public class UserController {

	private final PasswordEncoder passwordEncoder;
	private final UserService userService;

	public UserController(PasswordEncoder passwordEncoder, UserService userService) {
		this.passwordEncoder = passwordEncoder;
		this.userService = userService;
	}

	@PostMapping("/sign-up")
	public String signUp(AccountDto accountDto) {
		userService.createUser(accountDto.toEntity(passwordEncoder));
		return "redirect:/";
	}
}
