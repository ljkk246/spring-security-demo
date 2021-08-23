package com.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();

        http.formLogin();

        http.rememberMe()
                .userDetailsService(userDetailsService);
        //AnonymousAuthenticationFilter
        //지금까지는 user객체가 null이면 인증을 받지 않았다고 판단하고 자원에 접근하지 못하도록 막음.
        //이 개념이 AnonymousAuthenticationFilter에서도 동일하지만 AnonymousAuthenticationFilter에서는 null로 처리하지 않고 별도의 익명 사용자로 만듬.
        //user 객체가 null이면 익명 사용자용 인증객체를 만든다는게 차이점.
        //SecurityContextHoler에 익명사용자 토큰객체를 저장함.

        //익명사용자 필터는 언제 사용?
        //isAnonymous()-> true이면 로그인 버튼을 보여줌. isAuthenticated() -> true이면 로그아웃 버튼을 보여줌.

        //익명사용자 필터는 인증 객체를 세션에 저장하지 않는다.

        //AbstractSecurityInterceptor는 필터중 맨 마지막 단계에서 사용자에게 자원을 허용/비허용하는 '인가'처리를 담당한다.






    }
}
