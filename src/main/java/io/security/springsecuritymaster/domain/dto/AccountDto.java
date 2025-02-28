package io.security.springsecuritymaster.domain.dto;

import org.springframework.security.crypto.password.PasswordEncoder;

import io.security.springsecuritymaster.domain.entity.Account;

public record AccountDto(
	String id,
	String username,
	String password,
	int age,
	String roles
) {

	public Account toEntity(PasswordEncoder passwordEncoder) {
		return Account.create(username, passwordEncoder.encode(password), age, roles);
	}
}
