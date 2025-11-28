package app.controller;

import java.time.LocalDate;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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

import app.entity.Vagas;
import app.service.VagasService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/vagas")
@CrossOrigin ("*")
public class VagasController {

    @Autowired
    private VagasService vagasService;
    
    @PreAuthorize("hasAuthority('Empregador')")
    @PostMapping("/save")
    public ResponseEntity<String> save(@RequestBody Vagas vagas) {
        String mensagem = this.vagasService.save(vagas);
        return ResponseEntity.ok(mensagem);
    }
    
    @PreAuthorize("hasAuthority('Empregador')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> delete(@PathVariable long id) {
        String mensagem = this.vagasService.delete(id);
        return ResponseEntity.ok(mensagem);
    }
    @PreAuthorize("hasAuthority('Empregador')")
    @GetMapping("/findById/{id}")
    public ResponseEntity<Vagas> findById(@PathVariable long id) {
        Vagas vagas = this.vagasService.findById(id);
        return ResponseEntity.ok(vagas);
    }
    
    @PreAuthorize("hasAuthority('Empregador')")
    @PutMapping("/update/{id}")
    public ResponseEntity<String> update(@Valid @PathVariable long id, @RequestBody Vagas vagas) {
        String mensagem = this.vagasService.update(vagas, id);
        return ResponseEntity.ok(mensagem);
    }
    
    @GetMapping("/findAll")
    public ResponseEntity<List<Vagas>> findAll() {
        List<Vagas> lista = this.vagasService.findAll();
        return ResponseEntity.ok(lista);
    }
    
    @GetMapping("/findByTitulo")
    public ResponseEntity<List<Vagas>> findByTituloContainingIgnoreCase(@RequestParam String titulo) {
        return ResponseEntity.ok(this.vagasService.findByTituloContainingIgnoreCase(titulo));
    }

    @GetMapping("/findByRequisito")
    public ResponseEntity<List<Vagas>> findByRequisito(@RequestParam String requisito) {
        return ResponseEntity.ok(this.vagasService.findByRequisito(requisito));
    }

    @GetMapping("/findBySalario")
    public ResponseEntity<List<Vagas>> findBySalarioBetween(@RequestParam float salario1, @RequestParam float salario2) {
        return ResponseEntity.ok(this.vagasService.findBySalarioBetween(salario1, salario2));
    }

    @GetMapping("/findBySetor")
    public ResponseEntity<List<Vagas>> findBySetor(@RequestParam String setor) {
        return ResponseEntity.ok(this.vagasService.findBySetor(setor));
    }

    @GetMapping("/findByDataAnuncio")
    public ResponseEntity<List<Vagas>> findByDataAnuncio(@RequestParam LocalDate data) {
        return ResponseEntity.ok(this.vagasService.findByDataAnuncio(data));
    }

    @GetMapping("/findByTipo")
    public ResponseEntity<List<Vagas>> findByTipo(@RequestParam String tipo) {
        return ResponseEntity.ok(this.vagasService.findByTipo(tipo));
    }

    @GetMapping("/findByNivelExperiencia")
    public ResponseEntity<List<Vagas>> findByNivelExperiencia(@RequestParam String nivelExperiencia) {
        return ResponseEntity.ok(this.vagasService.findByNivelExperiencia(nivelExperiencia));
    }
}