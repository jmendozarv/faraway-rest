package com.canvia.smartview.rest.security;

import com.canvia.smartview.core.security.JWTService;
import com.canvia.smartview.core.security.JWTServiceImpl;
import com.canvia.smartview.core.security.SmartViewAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private JWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException{
		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
		
		if(!requiresAuthentication(header)) {			
			chain.doFilter(request, response);
			return;
		}
		SmartViewAuthentication authentication = null;
		if(jwtService.validate(header)) {
			authentication = new SmartViewAuthentication(jwtService.getUsername(header), null, jwtService.getRoles(header), jwtService.getUserDto(header));
		}
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}
	
	protected boolean requiresAuthentication(String header) {
		if(header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}
}
