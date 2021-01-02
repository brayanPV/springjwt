package datajpacom.example.proyectoconjpa.auth.service;

import java.util.Collection;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.io.IOException;

public interface JWTService {
    
    public String create(Authentication auth) throws JsonProcessingException;
    public boolean validate(String token);
    public Claims getClaims(String token);
    public String getUsername(String token);
    public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException, JsonParseException, JsonMappingException, java.io.IOException;
    public String resolve(String token);
}
