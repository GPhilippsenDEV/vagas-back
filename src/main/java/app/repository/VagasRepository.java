package app.repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import app.entity.Endereco;
import app.entity.Vagas;

public interface VagasRepository extends JpaRepository<Vagas, Long> {
	
	public List<Vagas> findByTituloContainingIgnoreCase(String titulo);
	
	public List<Vagas> findByRequisito(String requisito);
	
	public List<Vagas> findBySalarioBetween(float salario1, float salario2);
	
	public List<Vagas> findBySetor(String setor);
	
	public List<Vagas> findByDataAnuncio(LocalDate dataAnuncio);
	
	public List<Vagas> findByTipo(String tipo);
	
	public List<Vagas> findByNivelExperiencia(String nivelExperiencia);
	

}
