package com.canvia.smartview.rest.security;

import com.canvia.smartview.core.entity.dto.UserDto;
import com.canvia.smartview.core.security.JWTService;
import com.canvia.smartview.core.security.JWTServiceImpl;
import com.canvia.smartview.core.security.SmartViewAuthentication;
import com.canvia.smartview.core.util.ConstantsCore;
import com.canvia.smartview.rest.util.ConstantsRest;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

	private AuthenticationManager authenticationManager;
	private JWTService jwtService;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
		this.jwtService = jwtService;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		logger.info("attemptAuthentication.");
		String username=null;
		String password=null;
		
		try {
			UserDto userDto = new ObjectMapper().readValue(request.getInputStream(),UserDto.class);
			username= userDto.getUsername().trim();
			password=userDto.getPassword();
			logger.info("By username: " + username);
		} catch (JsonParseException e) {
			logger.error("JsonParseException: " + e.getMessage(), e);
		} catch (JsonMappingException e) {
			logger.error("JsonMappingException: " + e.getMessage(), e);
		} catch (IOException e) {
			logger.error("IOException: " + e.getMessage(), e);
		}

		return authenticationManager.authenticate(new SmartViewAuthentication(username, password));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
		logger.info("successfulAuthentication: " + authResult.getName());
		
		Map<String, Object> result = jwtService.create(authResult);
		String token = String.valueOf(result.get(ConstantsCore.KEY_TOKEN));
		
		response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);

		Map<String, Object> body = new HashMap<String, Object>();
		body.put(ConstantsCore.KEY_TOKEN, token);
		body.put(ConstantsCore.KEY_MESSAGE, String.format("Hola %s, has iniciado sesion!", ((User)authResult.getPrincipal()).getUsername() ));

		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(ConstantsRest.HTTP_CODE_OK);
		response.setContentType(ConstantsRest.APPLICATION_JSON);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		logger.error("unsuccessfulAuthentication: " + failed.getMessage());
		Map<String, Object> body = new HashMap<String, Object>();
		body.put(ConstantsCore.KEY_MESSAGE, ConstantsRest.ERROR_AUTHENTICATION_FAILED);
		body.put(ConstantsCore.KEY_ERROR, failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(ConstantsRest.HTTP_CODE_UNAUTHORIZED);
		response.setContentType(ConstantsRest.APPLICATION_JSON);
	}	
}
