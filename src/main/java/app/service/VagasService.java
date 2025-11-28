package app.service;

import java.time.LocalDate;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import app.entity.Empregador;
import app.entity.Endereco;
import app.entity.Vagas;
import app.repository.EmpregadorRepository;
import app.repository.EnderecoRepository;
import app.repository.VagasRepository;

@Service
public class VagasService {
	
	@Autowired
	private VagasRepository vagasRepository;
	
	@Autowired 
	private EnderecoRepository enderecoRepository;
	@Autowired 
	private EmpregadorRepository empregadorRepository;
	
	public String save(Vagas vagas) {
	/*	Empregador emp = this.empregadorRepository.findById(vagas.getEmpregador().getId()).get();
		List<Endereco> enderecos = emp.getEnderecos();
		
		for(int i = 0 ; i < enderecos.size(); i++) {
			if(enderecos.get(i).getCidade() == null)
				throw new RuntimeException("Nao e possivel cadastrar uma vaga com o endereco incompleto do empregador");
		}
		
		*/
		
		//arrumar isso aqui
//		Endereco endereco = this.enderecoRepository.findById(vagas.getEnderecos().getId()).get();
//		
//		if(endereco == null) {
//			throw new RuntimeException("Nao e possivel cadastrar uma vaga sem endereco");
//
//		}
//		
//		if(!endereco.isCadatroCompleto()) {
//			throw new RuntimeException("Nao e possivel cadastrar uma vaga com o endereco incompleto");
//
//		}
		this.vagasRepository.save(vagas);
		
		return "a Vaga " + vagas.getDescricao() + " foi salvo com sucesso";
	}
	
	public Vagas findById(long id) {
		
		Vagas vagas = this.vagasRepository.findById(id).get();
		
		return vagas;
	}
	
	public String update(Vagas vagas, long id) {
		vagas.setId(id);
		this.vagasRepository.save(vagas);
		return vagas.getDescricao() + " foi atualizado com sucesso!";
	}
	
	public List<Vagas> findAll(){
		
		List<Vagas> lista = this.vagasRepository.findAll();


		return lista;
	}
	
	public String delete(long id) {
		this.vagasRepository.deleteById(id);
		return "A Vaga foi deletado";
	}

	public List<Vagas> findByTituloContainingIgnoreCase(String titulo){
		return this.vagasRepository.findByTituloContainingIgnoreCase(titulo);
	}
	
	public List<Vagas> findByRequisito(String requisito){
		return this.vagasRepository.findByRequisito(requisito);
	}
	
	public List<Vagas> findBySalarioBetween(float salario1, float salario2){
		return this.vagasRepository.findBySalarioBetween(salario1, salario2);
	}
	
	public List<Vagas> findBySetor(String setor){
		return this.vagasRepository.findBySetor(setor);
	}
	
	public List<Vagas> findByDataAnuncio(LocalDate dataAnuncio){
		return this.vagasRepository.findByDataAnuncio(dataAnuncio);
	}
	
	public List<Vagas> findByTipo(String tipo){
		return this.vagasRepository.findByTipo(tipo);
	}
	
	public List<Vagas> findByNivelExperiencia(String nivelExperiencia){
		return this.vagasRepository.findByNivelExperiencia(nivelExperiencia);
	}
	
}
