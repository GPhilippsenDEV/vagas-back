package app.controller.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import app.controller.EmpregadorController;
import app.entity.Empregador;
import app.repository.EmpregadorRepository;
import app.service.EmpregadorService;

@SpringBootTest
public class EmpregadorControllerTest {
	
	@Autowired
	EmpregadorController empregadorController;
	
	@MockitoBean
	EmpregadorRepository empregadorRepository;
	
	@MockitoBean
	EmpregadorService empregadorService;
	
	@BeforeEach
	void setup() {
		
	    List<Empregador> lista = new ArrayList<>();
	    lista.add(new Empregador(0, "teste1", null, null, null, null, null, null));
	    lista.add(new Empregador());

	    when(empregadorRepository.findAll()).thenReturn(lista);
	}

	 /*@Test
	    @DisplayName("Deve retornar lista vazia de empregadores (integração com mock)")
	    void cenario001() {
	        ResponseEntity<List<Empregador>> retorno = this.empregadorController.findAll();
	        assertEquals(0, retorno.getBody().size());
	    }

	    @Test
	    @DisplayName("Deve lançar exceção ao tentar salvar empregador inválido")
	    void cenario002() {
	        Empregador empregadorZoado = new Empregador(0, "teste1", null, null, null, null, null, null);

	        when(empregadorRepository.save(Mockito.any())).thenReturn(empregadorZoado);

	        assertThrows(Exception.class, () -> {
	            this.empregadorController.save(empregadorZoado);
	        });
	    }

	    @Test
	    @DisplayName("Deve deletar empregador e retornar mensagem de sucesso com status 200")
	    void cenarioDeleteEmpregador() {
	        long id = 1L;
	        String mensagemEsperada = "O Empregador foi deletado";

	        when(empregadorService.delete(id)).thenReturn(mensagemEsperada);

	        ResponseEntity<String> resposta = empregadorController.delete(id);

	        assertEquals(200, resposta.getStatusCodeValue());
	        assertEquals(mensagemEsperada, resposta.getBody());
	        verify(empregadorService, times(1)).delete(id);
	    }

	    @Test
	    @DisplayName("Deve retornar empregador pelo ID com status 200")
	    void cenarioFindByIdEmpregador() {
	        long id = 1L;
	        Empregador mockEmpregador = new Empregador();
	        mockEmpregador.setId(id);
	        mockEmpregador.setNomeFantasia("Empresa Teste");

	        when(empregadorService.findById(id)).thenReturn(mockEmpregador);

	        ResponseEntity<Empregador> resposta = empregadorController.findById(id);

	        assertEquals(200, resposta.getStatusCodeValue());
	        assertEquals("Empresa Teste", resposta.getBody().getNomeFantasia());
	        verify(empregadorService, times(1)).findById(id);
	    }

	    @Test
	    @DisplayName("Deve atualizar empregador e retornar mensagem de sucesso com status 200")
	    void cenarioUpdateEmpregador() {
	        long id = 2L;
	        Empregador emp = new Empregador();
	        emp.setNomeFantasia("Atualizado");

	        String msg = "Atualizado foi atualizado com sucesso!";
	        when(empregadorService.update(emp, id)).thenReturn(msg);

	        ResponseEntity<String> resposta = empregadorController.update(id, emp);

	        assertEquals(200, resposta.getStatusCodeValue());
	        assertEquals(msg, resposta.getBody());
	        verify(empregadorService).update(emp, id);
	    }

	    @Test
	    @DisplayName("Deve retornar lista com empregadores que têm nome fantasia exato")
	    void cenarioFindByNomeFantasia() {
	        String nome = "Empresa";
	        Empregador emp = new Empregador();
	        emp.setNomeFantasia(nome);

	        when(empregadorService.findByNomeFantasia(nome)).thenReturn(Arrays.asList(emp));

	        List<Empregador> resultado = empregadorController.findByNomeFantansia(nome);

	        assertEquals(1, resultado.size());
	        assertEquals("Empresa", resultado.get(0).getNomeFantasia());
	        verify(empregadorService).findByNomeFantasia(nome);
	    }

	    @Test
	    @DisplayName("Deve retornar empregadores cujo nome fantasia contenha parte do texto informado")
	    void cenarioFindByNomeFantasiaContaining() {
	        String nome = "Emp";
	        Empregador emp = new Empregador();
	        emp.setNomeFantasia("EmpTest");

	        when(empregadorService.findByNomeFantasiaContaining(nome)).thenReturn(Arrays.asList(emp));

	        List<Empregador> resultado = empregadorController.findByNomeFantasiaContaining(nome);

	        assertEquals(1, resultado.size());
	        assertTrue(resultado.get(0).getNomeFantasia().contains(nome));
	        verify(empregadorService).findByNomeFantasiaContaining(nome);
	    }

	    @Test
	    @DisplayName("Deve retornar empregadores cujo CNPJ contenha parte do texto informado")
	    void cenarioFindByCnpjContaining() {
	        String cnpj = "123";
	        Empregador emp = new Empregador();
	        emp.setCnpj("12345678000195");

	        when(empregadorService.findByCnpjContaining(cnpj)).thenReturn(Arrays.asList(emp));

	        List<Empregador> resultado = empregadorController.findByCnpj(cnpj);

	        assertEquals(1, resultado.size());
	        assertTrue(resultado.get(0).getCnpj().contains(cnpj));
	        verify(empregadorService).findByCnpjContaining(cnpj);
	    }*/
	}


