package io.security.springsecuritymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.RequiredArgsConstructor;

@Entity
public class Account extends BaseEntity {

	@Column
	private String username;

	@Column
	private String password;

	@Column
	private int age;

	@Column
	private String roles;

	protected Account() {
	}

	private Account(String username, String password, int age, String roles) {
		this.username = username;
		this.password = password;
		this.age = age;
		this.roles = roles;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public int getAge() {
		return age;
	}

	public String getRoles() {
		return roles;
	}

	public static Account create(String username, String password, int age, String roles) {
		return new Account(username, password, age, roles);
	}
}
