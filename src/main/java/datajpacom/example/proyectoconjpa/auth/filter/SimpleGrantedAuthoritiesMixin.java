package datajpacom.example.proyectoconjpa.auth.filter;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthoritiesMixin {

    @JsonCreator
    public SimpleGrantedAuthoritiesMixin(@JsonProperty("authority") String role) {
    }
    
}
