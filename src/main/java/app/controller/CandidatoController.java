package app.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import app.entity.Candidato;
import app.service.CandidatoService_;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/candidato")
@CrossOrigin ("*")
@Validated
public class CandidatoController {
	
	@Autowired
    private CandidatoService_ candidatoService;

    @PostMapping("/save")
    public ResponseEntity<String> save(@RequestBody Candidato candidato) {
        String mensagem = this.candidatoService.save(candidato);
        return ResponseEntity.ok(mensagem);
    }

    @PreAuthorize("hasAuthority('Candidato')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> delete(@PathVariable long id) {
        String mensagem = this.candidatoService.delete(id);
        return ResponseEntity.ok(mensagem);
    }
    
    @PreAuthorize("hasAuthority('Candidato')or hasAuthority('Empregador') ")
    @GetMapping("/findById/{id}")
    public ResponseEntity<Candidato> findById(@PathVariable long id) {
        Candidato candidato = this.candidatoService.findById(id);
        return ResponseEntity.ok(candidato);
    }
    
    @PreAuthorize("hasAuthority('Candidato')or hasAuthority('Empregador') ")
    @GetMapping("/findCandidatoByIdUsuario/{id}")
    public ResponseEntity<Candidato> findCandidatoByIdUsuario(@PathVariable long id) {
        Candidato candidato = this.candidatoService.findCandidatoByIdUsuario(id);
        return ResponseEntity.ok(candidato);
    }
    
    @PreAuthorize("hasAuthority('Candidato')")
    @PutMapping("/update/{id}")
    public ResponseEntity<String> update(@Valid @PathVariable long id, @RequestBody Candidato candidato) {
        String mensagem = this.candidatoService.update(candidato, id);
        return ResponseEntity.ok(mensagem);
    }

    @PreAuthorize("hasAuthority('Empregador')")
    @GetMapping("/findAll/{numPage}")
    public ResponseEntity<Page<Candidato>> findAll(@PathVariable ("numPage")int numPage) {
        Page<Candidato> lista = this.candidatoService.findAll(numPage);
        return ResponseEntity.ok(lista);
    }

    @PreAuthorize("hasAuthority('Candidato')")
    @PostMapping("/inscricao")
    public ResponseEntity<String> inscricao(@RequestParam long idCandidato, @RequestParam long idVaga) {
        String mensagem = this.candidatoService.inscricao(idCandidato, idVaga);
        return ResponseEntity.ok(mensagem);
    }
    
    @PreAuthorize("hasAuthority('Empregador')")
    @GetMapping("/findByCpfContaining")
    public List<Candidato> findByCpfContaining(@RequestParam String cpf) {
        return candidatoService.findByCpfContaining(cpf);
    }

}