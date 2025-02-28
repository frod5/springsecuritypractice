package io.security.springsecuritymaster.domain.dto;

import org.springframework.security.crypto.password.PasswordEncoder;

import io.security.springsecuritymaster.domain.entity.Account;

public record AccountDto(
	Long id,
	String username,
	String password,
	int age,
	String roles
) {

	public Account toEntity(PasswordEncoder passwordEncoder) {
		return Account.create(username, passwordEncoder.encode(password), age, roles);
	}

	public AccountDto toDto(Account account) {
		return new AccountDto(account.getId(), account.getUsername(), account.getPassword(), account.getAge(), account.getRoles());
	}
}
