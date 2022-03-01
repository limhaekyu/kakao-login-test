package com.example.kakaologintest.domain;

import lombok.*;

import javax.persistence.*;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Long id;

    @Column
    private String userName; // id

    @Column
    private String password;

    @Column
    private String email;

    private String oauth; // 카카오 로그인이면 회원정보를 수정 못하게 하기위해

    @Enumerated(EnumType.STRING)
    private RoleType role; // USER, ADMIN
}
