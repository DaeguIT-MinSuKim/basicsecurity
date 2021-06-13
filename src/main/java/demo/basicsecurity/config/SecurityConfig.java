package demo.basicsecurity.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//인가
		http
			.authorizeRequests()
			.anyRequest()
			.authenticated()
			;
		
		//인증
		http.formLogin()
//			.loginPage("/loginPage")
			.defaultSuccessUrl("/")
			.failureUrl("/login")
			.usernameParameter("userId")
			.passwordParameter("passwd")
			.loginProcessingUrl("/login_proc")
			.successHandler(new AuthenticationSuccessHandler() {
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
						Authentication authentication) throws IOException, ServletException {
					System.out.println("authentication " + authentication.getName());
					response.sendRedirect("/");
				}
			})
			.failureHandler(new AuthenticationFailureHandler() {
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
						AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception " + exception.getMessage());
					response.sendRedirect("/");
				}
			})
			.permitAll() //.loginPage("/loginPage")에서는 모든 사용자가 인가되어야 되므로 허용
			;
		
		http.logout()							// 로그아웃 처리
        	.logoutUrl("/logout")				// 로그아웃 처리 URL
        	.logoutSuccessUrl("/login")			// 로그아웃 성공 후 이동페이지 default post방식
        	.addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
					HttpSession session = request.getSession();
					session.invalidate();
				}
			})		
        	.logoutSuccessHandler(new LogoutSuccessHandler() {// 로그아웃 성공 후 핸들러
				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
						throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			}) 	
        	.deleteCookies("JSESSIONID", "remember-me") 	// 로그아웃 후 쿠키 삭제
        	;
		
		http.rememberMe()
			.rememberMeParameter("remember") // 기본 파라미터명은 remember-me
			.tokenValiditySeconds(3600) 	 // 1시간 Default 는 14일
//			.alwaysRemember(true) 			 // 리멤버 미 기능이 활성화되지 않아도 항상 실행 false를 두는 것이 좋음.
			.userDetailsService(userDetailsService)
			;

	}
	
}
