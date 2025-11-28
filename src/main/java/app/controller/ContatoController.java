package app.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import app.entity.Contato;
import app.service.ContatoService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/contato")
public class ContatoController {
	
	@Autowired
	private ContatoService contatoService;

	@PostMapping("/save")
	public ResponseEntity<String> save(@RequestBody Contato contato) {
		String mensagem = this.contatoService.save(contato);
		return ResponseEntity.ok(mensagem);
	}
	
	@DeleteMapping("/delete/{id}")
	public ResponseEntity<String> delete(@PathVariable long id) {
		String mensagem = this.contatoService.delete(id);
		return ResponseEntity.ok(mensagem);
	}
	
	@GetMapping("/findById/{id}")
	public ResponseEntity<Contato> findById(@PathVariable long id) {
		Contato contato = this.contatoService.findById(id);
		return ResponseEntity.ok(contato);
	}
	
	@PutMapping("/update/{id}")
	public ResponseEntity<String> update(@Valid @PathVariable long id, @RequestBody Contato contato) {
		String mensagem = this.contatoService.update(contato, id);
		return ResponseEntity.ok(mensagem);
	}
	
	@GetMapping("/findAll")
	public ResponseEntity<List<Contato>> findAll() {
		List<Contato> lista = this.contatoService.findAll();
		return ResponseEntity.ok(lista);
	}
}