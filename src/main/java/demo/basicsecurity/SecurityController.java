package demo.basicsecurity;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
	
    @GetMapping("/")
    public String index(HttpSession session) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        SecurityContext context = (SecurityContext)session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication2 = context.getAuthentication();
        
        if (authentication.equals(authentication2)) {
            return "equals index";
        }else {
            return "different index";
        }
    }
    
    @GetMapping("/thread")
    public String thread() {
        String res;
        new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                        System.out.printf("authentication => %s%n", authentication);
                    }
                }).start();
        return "thread";
    }
/*
	@GetMapping("/")
	public String index() {
		return "home";
	}
	
	@GetMapping("loginPage")
	public String loginPage() {
		return "loginPage";
	}
	
	@GetMapping("/user")
	public String user() {
		return "user";
	}
	
	@GetMapping("/admin/pay")
	public String adminPay() {
		return "adminPay";
	}
	
	@GetMapping("/admin/**")
	public String admin() {
		return "admin";
	}
	
	//인증및인가 예외처리
    @GetMapping("/login")
    public String login() {
        return "login";
    }
	 
    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }
*/
}
