package io.security.springsecuritymaster.users.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.springsecuritymaster.domain.entity.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
}
