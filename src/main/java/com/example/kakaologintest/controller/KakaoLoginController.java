package com.example.kakaologintest.controller;

import com.example.kakaologintest.domain.KakaoProfile;
import com.example.kakaologintest.domain.OAuthToken;
import com.example.kakaologintest.domain.User;
import com.example.kakaologintest.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@RestController
public class KakaoLoginController {

    @Value("${cos.key}")
    private String cosKey;

    @Autowired(required = false)
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;


    @GetMapping("/auth/loginForm")
    public String loginForm(){
        return "user/loginForm";
    }

    @GetMapping("auth/kakao/callback")
    public String kakaoCallback(String code){

        // POST방식으로 key=value 데이터를 요청(카카오톡으로) RestTemplate 사용 -> Http요청 간편하게
        // Retrofit2(안드로이드 자주사용)
        // OkHttp
        // RestTemplate

        RestTemplate rt = new RestTemplate();
        // RestTemplate 사용으로 인한 401 error 때문에 추가
        rt.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        rt.setErrorHandler(new DefaultResponseErrorHandler(){
            public boolean hasError(ClientHttpResponse response) throws IOException{
                HttpStatus statusCode = response.getStatusCode();
                return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
            }
        });

        // HttpHeader Object 생성성
        HttpHeaders headers = new HttpHeaders();
        // Httpbody 데이터가 key=value 형태임을 알려주는 코드
        headers.add("Content-type","application/x-www-form-urlencoded;charset=utf-8");

        // params.add안 데이터 변수화 시켜서 사용
        // HttpBody Object 생성
        // body data
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type","authorization_code");
        params.add("client_id","f338db1fdf44b3583502edeb91546915");
        params.add("redirect_uri","http://localhost:8080/auth/kakao/callback");
        params.add("code",code);
        params.add("client_secret","DBeJvDYwP6JhL7vNQMU61b3XmeyyBdC3");

        // HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest =
                new HttpEntity<>(params, headers);


        // Http 요청하기, Post 방식으로, response 변수의 응답 받음
        ResponseEntity<String> response = rt.exchange(
                // 토큰 발급 요청 주소
                "https://kauth.kakao.com/oauth/token",
                // 요청 메서드
                HttpMethod.POST,
                // httpbody, httpheader 데이터
                kakaoTokenRequest,
                // 응답을 받을 타입
                String.class

        );

        // Gson, Json Simple, ObjectMapper 라이브러리 있다
        ObjectMapper objectMapper = new ObjectMapper();
        OAuthToken oauthToken = null;
        try {
            oauthToken = objectMapper.readValue(response.getBody(), OAuthToken.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }


        RestTemplate rt2 = new RestTemplate();
        // RestTemplate 사용으로 인한 401 error 때문에 추가
        rt2.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        rt2.setErrorHandler(new DefaultResponseErrorHandler(){
            public boolean hasError(ClientHttpResponse response) throws IOException{
                HttpStatus statusCode = response.getStatusCode();
                return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
            }
        });

        // HttpHeader Object 생성
        HttpHeaders headers2 = new HttpHeaders();
        // Httpbody 데이터가 key=value 형태임을 알려주는 코드
        headers2.add("Authorization","Bearer "+oauthToken.getAccess_token());
        headers2.add("Content-type","application/x-www-form-urlencoded;charset=utf-8");

        // HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest =
                new HttpEntity<>(headers2);


        // Http 요청하기, Post 방식으로, response 변수의 응답 받음
        ResponseEntity<String> response2 = rt2.exchange(
                // 토큰 발급 요청 주소
                "https://kapi.kakao.com/v2/user/me",
                // 요청 메서드
                HttpMethod.POST,
                // httpbody, httpheader 데이터
                kakaoProfileRequest,
                // 응답을 받을 타입
                String.class

        );

        ObjectMapper objectMapper2 = new ObjectMapper();
        KakaoProfile kakaoProfile = null;
        try {
            kakaoProfile = objectMapper2.readValue(response2.getBody(), KakaoProfile.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        // User 오브젝트 :  userName, password, email
        System.out.println("카카오 아이디(번호) : " + kakaoProfile.getId());
        System.out.println("카카오 이메일 : " + kakaoProfile.getKakao_account().getEmail());

        System.out.println("서버 유저네임 : "+kakaoProfile.getKakao_account().getEmail()+"_"+kakaoProfile.getId());
        System.out.println("서버 이메일 : "+kakaoProfile.getKakao_account().getEmail());
        // UUID -> 중복되지 않는 특정값 만드는 알고리즘
        System.out.println("서버 패스워드 : "+cosKey);

        User kakaoUser = User.builder()
                        .userName(kakaoProfile.getKakao_account().getEmail()+"_"+kakaoProfile.getId())
                        .password(cosKey)
                        .email(kakaoProfile.getKakao_account().getEmail())
                        .oauth("kakao")
                        .build();

        // 가입자 혹은 비 가입자 체크
        User originUser = userService.회원찾기(kakaoUser.getUserName());

        if(originUser==null){
            System.out.println("기존 회원이 아니기에 화원가입을 진행합니다.");
            userService.회원가입(kakaoUser);
        }

        System.out.println("로그인을 진행합니다.");
        // 로그인 처리
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(kakaoUser.getUserName(), cosKey));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return "회원가입 및 로그인 완료";
    }

}
