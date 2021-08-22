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

        http.logout() //로그아웃처리. POST 방식. (GET은 커스터마이징 필요)
                .logoutUrl("/logout")//로그 아웃 처리 url
                .logoutSuccessUrl("/login")//로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me")//로그아웃 후 쿠키들 삭제
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();//세션 무효화
                    }
                })//로그아웃 핸들러
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");//로그아웃 성공 후 리다이렉트
                    }
                });//로그아웃 성공 후 핸들러
        http.rememberMe()
                .rememberMeParameter("remember")//기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600)//리멤버 미 쿠키 만료 시간. 기본값은 14일
                .alwaysRemember(true)//리멤버미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);//리멤버 미를 쿠키를 인증할때 사용자를 조회 해야 하는데 그 때 필요한 서비스.
        // * remember-me 설명 *
        //인증이되었다는 건 그 사용자가 세션이 생성되었다느 것. 그리고 그 세션이 성공된 인증 객체를 담고 있음.
        //서버 같은 경우 인증에 성공한 그 사용자에게 세션을 생성할 때 가지고 있는 jsessionid를 응답에 실어서 보냄. 클라이언트는 jsessionid를 가지고 있음.
        //클라이언트는 다시 서버에 접속할 때 인증이 필요 없는데 그 이유는
        //클라이언트가 다시 세션에 접속할 때 서버는 세션id를 가지고 가서 매칭되는 세션을 꺼내서 인증된 사용자인지 판단해서 처리하게 됨.

        //그런데, editTHisCookie 크롬 툴로 JSESSIONID를 삭제하면, 서버에서는 세션을 못받아서 처음 접속하는 사용자인줄 알고 로그인페이지로 이동하게 됨.

        //이때 remember-me 쿠키를 체크하고 로그인 후 JSESSIONID를 다시 삭제하고 새로고침해보면, 이떄는 로그인페이지로 이동하지 않는다
        //그 이유는 JSESSIONID가 없다고 하더라도 remember-me 라는 쿠키의 값을 디코드,파싱해서 유저 계정을 얻어서 다시 인증을 시도하기 떄문이다.
    }
}
