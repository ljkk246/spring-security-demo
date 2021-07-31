package com.example.springsecuritydemo;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity //웹 보안 관련 클래스 import
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();//인가. 어떤 요청이라도 인가 프로세스 진행하도록 함.
        http.formLogin()
                //.loginPage("/loginPage")//사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")//로그인 성공 후 이동할 페이지 경로
                .failureForwardUrl("/login")//로그인 실패 후 이동할 페이지 경로
                .usernameParameter("userId")//로그인 폼 내 태그 파라미터명
                .passwordParameter("passwd")//로그인 폼 내 태그 파라미터명
                .loginProcessingUrl("/login_proc")//로그인 폼 내 로그인 액션 태그 파라미터명
                /*.successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("auth : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })//로그인 성공 후 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/loginPage");//인증 실패 후 다시 로그인 페이지
                    }
                })*///로그인 실패 후 핸들러
        .permitAll()//로그인 페이지는 접근이 가능해야 하므로 permitAll 설정.
        ;//인증http.
    }
}
