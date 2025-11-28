package app.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import app.entity.Endereco;

public interface EnderecoRepository extends JpaRepository<Endereco, Long> {
	List<Endereco> findByCidade(String cidade);
	List<Endereco> findByCidadeContaining(String cidade);
	List<Endereco> findByEstado(String estado);
    List<Endereco> findByEstadoContaining(String estado);

}
