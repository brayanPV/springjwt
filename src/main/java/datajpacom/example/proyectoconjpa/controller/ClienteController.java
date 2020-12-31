package datajpacom.example.proyectoconjpa.controller;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import datajpacom.example.proyectoconjpa.entities.Cliente;
import datajpacom.example.proyectoconjpa.service.ClienteServiceImp;
import datajpacom.example.proyectoconjpa.service.UploadFileServiceImp;
import datajpacom.example.proyectoconjpa.util.paginator.PageRender;

@Controller
@SessionAttributes("cliente")
public class ClienteController {

    protected final Log logger = LogFactory.getLog(this.getClass());

    //
    @Autowired
    private ClienteServiceImp clienteService;

    @Autowired
    private UploadFileServiceImp uploadFileService;

    //Rest 
    @RequestMapping(value = {"/api/listar"})
    public @ResponseBody List<Cliente> listarRest(){
        return clienteService.findAll();
    }

    @RequestMapping(value = {"/listar", "/"})
    public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model,  Authentication authentication, HttpServletRequest request) {


        if(authentication != null){
            logger.info("Hola usuario ".concat(authentication.getName()));
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth != null){
            logger.info("Estatica Hola usuario ".concat(auth.getName()));
        }

       /* if(hasRole("ROLE_ADMIN")){
            logger.info("Hola ".concat(auth.getName()).concat(" tienes acceso"));
        }else{
            logger.info("Hola ".concat(auth.getName()).concat(" no tienes acceso"));
        }*/

        SecurityContextHolderAwareRequestWrapper securityContext = new SecurityContextHolderAwareRequestWrapper(request, "ROLE_");
        if(securityContext.isUserInRole("ADMIN")){
            logger.info("Hola ".concat(auth.getName()).concat(" tienes acceso"));
        }else{
            logger.info("Hola ".concat(auth.getName()).concat(" no tienes acceso"));
        }
        
        Pageable pageRequest = PageRequest.of(page, 5);
        Page<Cliente> clientes = clienteService.findAll(pageRequest);
        PageRender<Cliente> pageRender = new PageRender<>("/listar", clientes);
        model.addAttribute("titulo", "listado de clientes");
        model.addAttribute("clientes", clientes);
        model.addAttribute("page", pageRender);
        return "listar";
    }

    @RequestMapping(value = "/form")
    public String crear(Model model) {
        model.addAttribute("titulo", "formularion de cliente");
        Cliente cliente = new Cliente();
        model.addAttribute("cliente", cliente);
        return "form";
    }

    @Secured("ROLE_ADMIN")
    @RequestMapping(value = "/form", method = RequestMethod.POST)
    public String guardar(@Valid Cliente cliente, BindingResult result, Model model,
            @RequestParam("file") MultipartFile foto, RedirectAttributes flash, SessionStatus status) {
        if (result.hasErrors()) {
            model.addAttribute("titulo", "formularion de cliente");
            return "form";
        } else {

            if (!foto.isEmpty()) {

                if (cliente.getId() != null && cliente.getId() > 0 && cliente.getFoto() != null
                        && cliente.getFoto().length() > 0) {

                    uploadFileService.delete(cliente.getFoto());
                }
                String uniqueFileName = null;
                try {
                    uniqueFileName = uploadFileService.copy(foto);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                flash.addFlashAttribute("info", "Se ha subido correctamente " + foto.getOriginalFilename());
                cliente.setFoto(uniqueFileName);
                // String rootPath = "C://Temp//uploads";

            }
            String mensajeFlash = (cliente.getId() != null) ? "Cliente editado con exito" : "Cliente creado con exito";
            clienteService.save(cliente);
            status.setComplete();
            flash.addFlashAttribute("success", mensajeFlash);
            return "redirect:listar";

        }
    }

    @Secured("ROLE_ADMIN")
    @RequestMapping(value = "/form/{id}")
    public String editar(@PathVariable(value = "id") Long id, Map<String, Object> model, RedirectAttributes flash) {
        Cliente cliente = null;
        if (id > 0) {
            cliente = clienteService.findOne(id);
            if (cliente == null) {
                flash.addFlashAttribute("error", "El ID del cliente no existe en la base de datos");
                return "redirect:/listar";
            }
        } else {
            flash.addFlashAttribute("error", "El ID del cliente no puede ser 0");
            return "redirect:/listar";
        }
        model.put("cliente", cliente);
        model.put("titulo", "editar cliente");
        return "form";
    }

    @Secured("ROLE_ADMIN")
    @RequestMapping(value = "/eliminar/{id}")
    public String eliminar(@PathVariable(value = "id") Long id, RedirectAttributes flash) {
        if (id > 0) {
            Cliente cliente = clienteService.findOne(id);

            clienteService.delete(id);
            flash.addFlashAttribute("success", "Cliente eliminado con exito");

            if (uploadFileService.delete(cliente.getFoto())) {
                flash.addFlashAttribute("info", "Foto " + cliente.getFoto() + " eliminada con exito");
            }

        }
        return "redirect:/listar";
    }

    //@Secured("ROLE_USER")
    //hasAnyRole('rol1', 'rol2')
    @PreAuthorize("hasRole('ROLE_USER')")   
    @RequestMapping(value = "/ver/{id}")
    public String ver(@PathVariable(value = "id") Long id, Map<String, Object> model, RedirectAttributes flash) {
        //Cliente cliente = clienteService.findOne(id);
        Cliente cliente = clienteService.fetchByIdWithFacturas(id);
        if (cliente == null) {
            flash.addFlashAttribute("error", "El cliente no existe en la base de datos");
            return "redirect:/listar";
        }
        model.put("cliente", cliente);
        model.put("titulo", "Detalle del cliente: " + cliente.getNombre());
        return "ver";
    }

    //varios roles
    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    @GetMapping(value = "/uploads/{filename:.+}")
    public ResponseEntity<Resource> verFoto(@PathVariable String filename) {

        Resource recurso = null;
        try {
            recurso = uploadFileService.load(filename);
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + recurso.getFilename() + "\"")
                .body(recurso);
    }

    private boolean hasRole(String role){
        SecurityContext context = SecurityContextHolder.getContext();
        if(context==null){
            return false;
        }
        Authentication auth= context.getAuthentication();
        if(auth==null){
            return false;
        }
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        /*for(GrantedAuthority authority: authorities){
            if(role.equals(authority.getAuthority())){
                return true;
            }
        }
        return false;*/
        return authorities.contains(new SimpleGrantedAuthority(role));
    }

}
