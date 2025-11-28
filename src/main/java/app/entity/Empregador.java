package app.entity;

import java.util.List;

import org.hibernate.validator.constraints.br.CNPJ;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import app.auth.Usuario;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity

public class Empregador {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	@NotBlank(message = "Nome Fantasia nao pode ser null")
	private String nomeFantasia;
	@NotBlank(message = "Razao social nao pode ser null")
	private String razaoSocial;
	@CNPJ
	@NotBlank(message = "CNPJ nao pode ser null")
	private String cnpj;
	
	//@NotEmpty(message = "Empregador precisa ter um contato")
	@OneToMany(mappedBy = "empregador", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("empregador")
	private List<Contato> contatos;
	
	//@NotEmpty(message = "Empregador precisa de um endereço")
	@OneToMany(mappedBy = "empregador", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("empregador")
	private List<Endereco> enderecos;
	
	@OneToMany(mappedBy = "empregador")
	@JsonIgnoreProperties("empregador")
	private List<Vagas> vagas;
	
	@ManyToOne(cascade = CascadeType.ALL)
	private Usuario usuario;
	

}
