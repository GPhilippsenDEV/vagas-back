package app.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import app.entity.Endereco;
import app.repository.EnderecoRepository;

@Service
public class EnderecoService {
	
	@Autowired
	private EnderecoRepository enderecoRepository;
	
	public String save(Endereco endereco) {
		
		if(endereco.getCidade() == null || endereco.getRua() == null || endereco.getNumero() == null) {
			endereco.setCadatroCompleto(false);
		}else
			endereco.setCadatroCompleto(true);
		
		this.enderecoRepository.save(endereco);
		
		return "o Endereco " + endereco.getRua() + " foi salvo com sucesso";
	}
	
	public Endereco findById(long id) {
		
		Endereco endereco = this.enderecoRepository.findById(id).get();
		
		return endereco;
	}
	
	public String update(Endereco endereco, long id) {
		endereco.setId(id);
		this.enderecoRepository.save(endereco);
		return endereco.getRua() + " foi atualizado com sucesso!";
	}
	
	public List<Endereco> findAll(){
		
		List<Endereco> lista = this.enderecoRepository.findAll();


		return lista;
	}
	
	public String delete(long id) {
		this.enderecoRepository.deleteById(id);
		return "O Endereco foi deletado";
	}
	public List<Endereco> findByCidade(String cidade){
		
		List<Endereco> lista = this.enderecoRepository.findByCidade(cidade);
		return lista;
}
	
	public List<Endereco> findByCidadeContaining(String cidade){
	
	List<Endereco> lista = this.enderecoRepository.findByCidadeContaining(cidade);
	return lista;
}
	
	public List<Endereco> findByEstado(String estado){
	
	List<Endereco> lista = this.enderecoRepository.findByEstado(estado);
	return lista;
	
}
	
	public List<Endereco> findByEstadoContaining(String estado){
	
	List<Endereco> lista = this.enderecoRepository.findByEstadoContaining(estado);
	return lista;
}

	
	

}
