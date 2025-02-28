package io.security.springsecuritymaster.users.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.springsecuritymaster.domain.entity.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
	Optional<Account> findByUsername(String username);
}
