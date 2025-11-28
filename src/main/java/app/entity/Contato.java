package app.entity;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.validation.constraints.Email;
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

public class Contato {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	private String telefone;
	@NotBlank(message = "celular nao pode ser null")
	private String celular;
	@Email
	@NotBlank(message = "Email nao pode ser null")
	private String email;
	
	@ManyToOne
	@JsonIgnoreProperties("contatos")
	private Candidato candidato;
	
	@ManyToOne
	@JsonIgnoreProperties("contatos")
	private Empregador empregador;
}
