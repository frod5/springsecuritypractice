package io.security.springsecuritymaster.users.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.users.repository.UserRepository;

@Service
public class UserService {

	private final UserRepository userRepository;

	public UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Transactional
	public void createUser(Account account) {
		userRepository.save(account);
	}
}
