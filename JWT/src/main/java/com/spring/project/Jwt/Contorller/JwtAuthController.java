package com.spring.project.Jwt.Contorller;

import com.spring.project.Jwt.Model.AuthRequest;
import com.spring.project.Jwt.Services.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class JwtAuthController {

    @Autowired
    JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthRequest authRequest){
        if("user123".equals(authRequest.getUserName()) && "password".equals(authRequest.getPassword())){
            String  token  = jwtUtil.generateToken(authRequest.getUserName());
            return ResponseEntity.ok(token);
        }
        else{
            System.out.println("Unautherized");
            return ResponseEntity.status(401).body(null);
        }
    }

    @GetMapping("/validate")
    public ResponseEntity<String> authentication(@RequestHeader("Authorization") String authorizationHeader) throws Exception {
        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")){
            return ResponseEntity.status(400).body("Invalid authorization header");
        }

        String token = authorizationHeader.substring(7);
        if(jwtUtil.validateToken(token)){
            String userId = jwtUtil.extractUserId(token);
            return ResponseEntity.ok("token is valid userId :" + userId);
        }else {
            return ResponseEntity.status(401).body("Invalid Token");
        }

    }
}
