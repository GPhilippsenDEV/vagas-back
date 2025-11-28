package app.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import app.entity.Empregador;
import app.repository.EmpregadorRepository;
import app.repository.EnderecoRepository;

@Service
public class EmpregadorService {
	
	@Autowired
	private EmpregadorRepository empregadorRepository;
	
	@Autowired 
	private EnderecoRepository enderecoRepository;
	

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	public String save(Empregador empregador) {
		
		List<Empregador> emp = this.empregadorRepository.findByCnpjContaining(empregador.getCnpj());
		if(!emp.isEmpty()) {
			throw new RuntimeException("Ja existe um empregador cadastrado com o "+emp.get(0).getCnpj());
		}
		
		if(empregador.getEnderecos() != null) {
			for(int i=0; i<empregador.getEnderecos().size(); i++) {
				empregador.getEnderecos().get(i).setEmpregador(empregador);
			}
		}
		
		//
		String senhaCrip = this.bCryptPasswordEncoder.encode(empregador.getUsuario().getPassword());
		empregador.getUsuario().setPassword(senhaCrip);
		//
		
		this.empregadorRepository.save(empregador);
		
		return "o Empregador " + empregador.getNomeFantasia() + " de CNPJ: " + empregador.getCnpj() + " foi salvo com sucesso";
	}
	
	public Empregador findById(long id) {
		
		Empregador empregador = this.empregadorRepository.findById(id).get();
		
		return empregador;
	}
	
	public String update(Empregador empregador, long id) {
		empregador.setId(id);
		
		
		if(empregador.getEnderecos() != null) {
			for(int i=0; i<empregador.getEnderecos().size(); i++) {
				empregador.getEnderecos().get(i).setEmpregador(empregador);
			}
		}
		
		
		this.empregadorRepository.save(empregador);
		return empregador.getNomeFantasia() + " foi atualizado com sucesso!";
	}
	
	public List<Empregador> findAll(){
		
		List<Empregador> lista = this.empregadorRepository.findAll();


		return lista;
	}
	
	public String delete(long id) {
		this.empregadorRepository.deleteById(id);
		return "O Empregador foi deletado";
	}
	
	 public List<Empregador> findByNomeFantasia(String nomeFantasia) {
	        return empregadorRepository.findByNomeFantasia(nomeFantasia);
	    }

	    public List<Empregador> findByNomeFantasiaContaining(String nomeFantasia) {
	        return empregadorRepository.findByNomeFantasiaContaining(nomeFantasia);
	    }
	    
	    
	    public List<Empregador> findByCnpjContaining(String cnpj) {
	        return empregadorRepository.findByCnpjContaining(cnpj);
	    }
	    
	    
	    

		}

