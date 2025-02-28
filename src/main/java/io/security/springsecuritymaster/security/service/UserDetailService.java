package io.security.springsecuritymaster.security.service;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.springsecuritymaster.domain.dto.AccountContext;
import io.security.springsecuritymaster.domain.dto.AccountDto;
import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.users.repository.UserRepository;

@Service
public class UserDetailService implements UserDetailsService {

	private final UserRepository userRepository;

	public UserDetailService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Account account = userRepository.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

		List<GrantedAuthority> roles = List.of(new SimpleGrantedAuthority(account.getRoles()));

		AccountDto accountDto = new AccountDto(account.getId(), account.getUsername(), account.getPassword(),
			account.getAge(), account.getRoles());

		return new AccountContext(accountDto, roles);
	}
}
