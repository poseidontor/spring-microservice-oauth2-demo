package com.example.userservice.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import lombok.Setter;

@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
public class BaseEntity {

    @CreatedBy
    @Column(name = "createdBy")
    private String createdBy;

    @CreatedDate
    @Column(name = "createdAt")
    private LocalDateTime createdDate;

    @LastModifiedBy
    @Column(name = "updatedBy")
    private String lastModifiedBy;

    @LastModifiedDate
    @Column(name = "updatedAt")
    private LocalDateTime lastModifiedDate;

}
