package app.entity;

import java.time.LocalDate;
import java.util.List;

import org.hibernate.validator.constraints.br.CPF;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import app.auth.Usuario;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity

public class Candidato {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	@NotBlank(message = "nome nao pode ser null")
	private String nome;
	@CPF (message = "CPF tem que ser validado")
	@NotBlank(message = "CPF nao pode ser null")
	private String cpf;
	@NotNull(message = "Data de Nascimento nao pode ser null")
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
	private LocalDate dataNascimento;
	
	//@NotEmpty(message = "Candidato precisa de um contato")
	@OneToMany(mappedBy = "candidato", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("candidato")
	private List<Contato> contatos;
	
	//@NotEmpty(message = "Candidato precisa de um endereço")
	@OneToMany(mappedBy = "candidato", cascade = CascadeType.ALL, orphanRemoval = true)
	@JsonIgnoreProperties("candidato")
	private List<Endereco> enderecos;
	
	@ManyToMany
	@JoinTable(name="vagas_candidato")
	@JsonIgnoreProperties("candidatos")
	private List<Vagas> vagas;
	
	@ManyToOne(cascade = CascadeType.ALL)
	private Usuario usuario;
	

}
