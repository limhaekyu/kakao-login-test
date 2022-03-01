package com.example.kakaologintest.service;

import com.example.kakaologintest.domain.RoleType;
import com.example.kakaologintest.domain.User;
import com.example.kakaologintest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Transactional
    public void 회원가입(User user) {
        String rawPassword = user.getPassword();
        String encPassword = encoder.encode(rawPassword);
        user.setPassword(encPassword);
        user.setRole(RoleType.USER);
        userRepository.save(user);

    }

    @Transactional(readOnly = true)
    public User 회원찾기(String userName) {

        User user = userRepository.findByUserName(userName).orElseGet(()->{
            return null;
        });
        return user;
    }
}
