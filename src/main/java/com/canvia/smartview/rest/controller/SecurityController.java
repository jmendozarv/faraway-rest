package com.canvia.smartview.rest.controller;

import com.canvia.smartview.core.entity.dto.UserDto;
import com.canvia.smartview.core.exception.SmartViewException;
import com.canvia.smartview.core.security.JWTService;
import com.canvia.smartview.core.service.ISecurityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/security")
public class SecurityController {
	private Logger logger = LoggerFactory.getLogger(SecurityController.class);

	@Autowired
	private JWTService jwtService;
	
	@Autowired
	private ISecurityService securityService;

	@GetMapping("/username/{username}") 
	public UserDto findAccountByUsername(@PathVariable String username) throws SmartViewException {
		logger.info("GET account - findAccountByUsername");
		UserDto userDto = securityService.findUserByUsername(username);
		logger.info("userId: " + userDto.getUserId());
		logger.info("username: " + userDto.getUsername());
		logger.info("password: " + userDto.getPassword());
		return userDto;
	}

}
