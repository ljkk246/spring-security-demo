# 01. 스프링 시큐리티 기본 API 및 Filter 이해

### 1) 프로젝트 구성 및 의존성 추가

build.gradle 의존성 추가

    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'

### 2) 사용자 정의 보안 기능 구현

``` 
@Configuration
@EnableWebSecurity //웹 보안 관련 클래스 import 한다.
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
@Override
protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests() //인가부분.
        .anyRequest().authenticated();// 어떤 요청이라도 인가 프로세스 진행하도록 함.
        http.formLogin();//인증부분. form 로그인 방식
    }
}
```

### 3) Form Login 인증

```
http.formLogin()
                .loginPage("/loginPage")//사용자 정의 로그인 페이지
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
        ;
```

### 4) Form Login 인증필터 : UsernamePasswordAuthenticationFilter

### 5) Logout 처리, LogoutFilter

```
 http.logout() //로그아웃처리. POST 방식. (GET은 커스터마이징 필요)
                .logoutUrl("/logout")//로그 아웃 처리 url
                .logoutSuccessUrl("/login")//로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me")//로그아웃 후 쿠키들 삭제
               .addLogoutHandler(new LogoutHandler() {
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
```





