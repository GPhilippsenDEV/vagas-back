package app.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import app.entity.Candidato;
import app.repository.CandidatoRepository;
@Service
public class CandidatoService_ {
	
	@Autowired
	private CandidatoRepository candidatoRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	public String save(Candidato candidato) {
		
		List<Candidato> cand = this.candidatoRepository.findByCpfContaining(candidato.getCpf());
		if(cand != null && !cand.isEmpty()) {
			throw new RuntimeException("Ja existe um candidato cadastrado com o "+cand.get(0).getCpf());
		}
		
		if(candidato.getEnderecos() != null) {
			for(int i=0; i<candidato.getEnderecos().size(); i++) {
				candidato.getEnderecos().get(i).setCandidato(candidato);
			}
		}
		
		//
		String senhaCrip = this.bCryptPasswordEncoder.encode(candidato.getUsuario().getPassword());
		candidato.getUsuario().setPassword(senhaCrip);
		//
		
		this.candidatoRepository.save(candidato);
		
		return "o Candidato " + candidato.getNome() + " foi salvo com sucesso";
	}
	
	public Candidato findById(long id) {
		
		Candidato candidato = this.candidatoRepository.findById(id).get();
		
		return candidato;
	}
	
public Candidato findCandidatoByIdUsuario(long id) {
		
		Candidato candidato = this.candidatoRepository.findCandidatoByIdUsuario(id).get();
		
		return candidato;
	}
	
	public String update(Candidato candidato, long id) {
		candidato.setId(id);
		
		if(candidato.getEnderecos() != null) {
			for(int i=0; i<candidato.getEnderecos().size(); i++) {
				candidato.getEnderecos().get(i).setCandidato(candidato);
			}
		}
		
		
		this.candidatoRepository.save(candidato);
		return candidato.getNome() + " foi atualizado com sucesso!";
	}
	
	public Page<Candidato> findAll(int numPage){
		int totalPorPagina = 5;
		PageRequest pageRequest = PageRequest.of(numPage-1, totalPorPagina);
		return this.candidatoRepository.findAll(pageRequest);
	}
	
	public String delete(long id) {
		this.candidatoRepository.deleteById(id);
		return "O Candidato foi deletado";
	}
	
	public String inscricao(long idCandidato, long idVaga) {
		this.candidatoRepository.inscricao(idCandidato, idVaga);
		
		return "inscricao realizada com sucesso";
		
	}
	public List<Candidato> findByCpfContaining(String cpf) {
             
		return candidatoRepository.findByCpfContaining(cpf);
   }
	
	//dfhbdufhufhd
	
}