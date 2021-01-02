package datajpacom.example.proyectoconjpa.auth.filter;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import datajpacom.example.proyectoconjpa.auth.service.JWTService;
import datajpacom.example.proyectoconjpa.auth.service.JWTServiceImpl;


public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private JWTService jwtService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String header = request.getHeader(JWTServiceImpl.HEADER_STRING);
        if (!requiresAuthenticacion(header)) {
            chain.doFilter(request, response);
            return;
        }
       
        UsernamePasswordAuthenticationToken authenticacion = null;

        if(jwtService.validate(header)){
            authenticacion = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));
        }


        SecurityContextHolder.getContext().setAuthentication(authenticacion);
        chain.doFilter(request, response);

    }

    protected boolean requiresAuthenticacion(String header) {
        if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
            return false;
        }
        return true;
    }
}
