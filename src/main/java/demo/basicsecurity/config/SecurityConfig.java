package demo.basicsecurity.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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

	/* 
	@Override
	protected void configure(HttpSecurity http) throws Exception { 
		//인가
		http
			.authorizeRequests()
			.anyRequest()
			.authenticated()
			;
		
		//인증
		http.formLogin();
//			.loginPage("/loginPage")
//			.defaultSuccessUrl("/")
//			.failureUrl("/login")
//			.usernameParameter("userId")
//			.passwordParameter("passwd")
//			.loginProcessingUrl("/login_proc")
//			.successHandler(new AuthenticationSuccessHandler() {
//				@Override
//				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//						Authentication authentication) throws IOException, ServletException {
//					System.out.println("authentication " + authentication.getName());
//					response.sendRedirect("/");
//				}
//			})
//			.failureHandler(new AuthenticationFailureHandler() {
//				@Override
//				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
//						AuthenticationException exception) throws IOException, ServletException {
//					System.out.println("exception " + exception.getMessage());
//					response.sendRedirect("/");
//				}
//			})
//			.permitAll() //.loginPage("/loginPage")에서는 모든 사용자가 인가되어야 되므로 허용
//			;
		
//		http.logout()							// 로그아웃 처리
//        	.logoutUrl("/logout")				// 로그아웃 처리 URL
//        	.logoutSuccessUrl("/login")			// 로그아웃 성공 후 이동페이지 default post방식
//        	.addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
//				@Override
//				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//					HttpSession session = request.getSession();
//					session.invalidate();
//				}
//			})		
//        	.logoutSuccessHandler(new LogoutSuccessHandler() {// 로그아웃 성공 후 핸들러
//				@Override
//				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
//						throws IOException, ServletException {
//					response.sendRedirect("/login");
//				}
//			}) 	
//        	.deleteCookies("JSESSIONID", "remember-me") 	// 로그아웃 후 쿠키 삭제
//        	;
//		
//		http.rememberMe()
//			.rememberMeParameter("remember-me") // 기본 파라미터명은 remember-me
//			.tokenValiditySeconds(3600) 	 // 1시간 Default 는 14일
////			.alwaysRemember(true) 			 // 리멤버 미 기능이 활성화되지 않아도 항상 실행 false를 두는 것이 좋음.
//			.userDetailsService(userDetailsService)
//			;
		
		
//        http.sessionManagement()
//	        .maximumSessions(1)                // 최대 허용 가능 세션 수 , -1 : 무제한 로그인 세션 허용
//	        .maxSessionsPreventsLogin(true)    // 동시 로그인 차단함(2번째 경우), 기본값 false (첫번째 경우): 기존 세션 만료(default)
////	        .invalidSessionUrl("/invalid")     // 세션이 유효하지 않을 때 이동 할 페이지
////	        .expiredUrl("/expired ")           // invalidSessionUrl과 동시에 지정될 경우 invalidSessionUrl우선
//	        ;

		http.sessionManagement()
			.maximumSessions(1) 
			.maxSessionsPreventsLogin(false);
	}
*/
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//메모리 방식
		auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER"); //{noop} 평문저장 암호화형태
//		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS"); //{noop} 평문저장 암호화형태
//		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN"); //{noop} 평문저장 암호화형태
		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER"); //{noop} 평문저장 암호화형태
		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER"); //{noop} 평문저장 암호화형태
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception { 
		http
			.authorizeRequests()
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin/pay").hasRole("ADMIN")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
			.anyRequest().authenticated();
		
		http
			.formLogin();
	}
}
