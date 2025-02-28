package io.security.springsecuritymaster.domain.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;

@MappedSuperclass
public abstract class BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column
	@CreationTimestamp
	private LocalDateTime created;

	@Column
	@UpdateTimestamp
	private LocalDateTime updated;

	protected BaseEntity() {
	}

	public Long getId() {
		return id;
	}

	public LocalDateTime getCreated() {
		return created;
	}

	public LocalDateTime getUpdated() {
		return updated;
	}
}
