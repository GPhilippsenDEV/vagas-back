package app.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import app.entity.Contato;

public interface ContatoRepository extends JpaRepository<Contato, Long> {
	
	public Contato findByEmail(String email);

}

