package com.example.kakaologintest.config.auth;

import com.example.kakaologintest.domain.User;
import com.example.kakaologintest.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PrincipalDetailService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 스프링이 로그인 요청을 가로챌 때, username, password 2개를 가로채는데
    // password 부분 처리는 알아서
    // username이 DB에 있는지만 확인해준다.
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException{
        User principal = userRepository.findByUserName(userName)
                .orElseThrow(()->{
                   return new UsernameNotFoundException("해당 사용자를 찾을 수 없습니다. : "+userName);
                });
        return new PrincipalDetail(principal); // 시큐리티 세션에 유저 정보가 저장
    }

}
