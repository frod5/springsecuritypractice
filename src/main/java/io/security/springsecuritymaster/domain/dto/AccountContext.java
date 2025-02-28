package io.security.springsecuritymaster.domain.dto;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class AccountContext implements UserDetails {
	private final AccountDto dto;
	private final List<GrantedAuthority> authorities;

	public AccountContext(AccountDto dto, List<GrantedAuthority> authorities) {
		this.dto = dto;
		this.authorities = authorities;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return dto.password();
	}

	@Override
	public String getUsername() {
		return dto.username();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
