package app.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import app.entity.Endereco;
import app.service.EnderecoService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/endereco")
public class EnderecoController {

    @Autowired
    private EnderecoService enderecoService;

    @PostMapping("/save")
    public ResponseEntity<String> save(@RequestBody Endereco endereco) {
        String mensagem = this.enderecoService.save(endereco);
        return ResponseEntity.ok(mensagem);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> delete(@PathVariable long id) {
        String mensagem = this.enderecoService.delete(id);
        return ResponseEntity.ok(mensagem);
    }

    @GetMapping("/findById/{id}")
    public ResponseEntity<Endereco> findById(@PathVariable long id) {
        Endereco endereco = this.enderecoService.findById(id);
        return ResponseEntity.ok(endereco);
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<String> update(@Valid @PathVariable long id, @RequestBody Endereco endereco) {
        String mensagem = this.enderecoService.update(endereco, id);
        return ResponseEntity.ok(mensagem);
    }

    @GetMapping("/findAll")
    public ResponseEntity<List<Endereco>> findAll() {
        List<Endereco> lista = this.enderecoService.findAll();
        return ResponseEntity.ok(lista);
    }

    @GetMapping("/findByCidade")
    public ResponseEntity<List<Endereco>> findByCidade(@RequestParam String cidade) {
        List<Endereco> lista = this.enderecoService.findByCidade(cidade);
        return ResponseEntity.ok(lista);
    }

    @GetMapping("/findByEstado")
    public ResponseEntity<List<Endereco>> findByEstado(@RequestParam String estado) {
        List<Endereco> lista = this.enderecoService.findByEstado(estado);
        return ResponseEntity.ok(lista);
    }

    @GetMapping("/findByCidadeContaining")
    public ResponseEntity<List<Endereco>> findByCidadeContaining(@RequestParam String cidade) {
        List<Endereco> lista = this.enderecoService.findByCidadeContaining(cidade);
        return ResponseEntity.ok(lista);
    }

    @GetMapping("/findByEstadoContaining")
    public ResponseEntity<List<Endereco>> findByEstadoContaining(@RequestParam String estado) {
        List<Endereco> lista = this.enderecoService.findByEstadoContaining(estado);
        return ResponseEntity.ok(lista);
    }
}