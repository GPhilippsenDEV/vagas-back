package app.service.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import app.entity.Candidato;
import app.repository.CandidatoRepository;
import app.service.CandidatoService_;

@SpringBootTest
public class CandidatoServiceTest {
	
	
	@Autowired
	CandidatoService_ candidatoService;
	
	@MockitoBean
	CandidatoRepository candidatoRepository;
	
	@BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
	
	
	
	/*@Test
    @DisplayName("Deve encontrar candidato por ID com sucesso")
    void testFindById() {
        Candidato candidato = new Candidato();
        candidato.setId(1L);
        candidato.setNome("Test Candidato");

        when(candidatoRepository.findById(1L)).thenReturn(java.util.Optional.of(candidato));

        Candidato result = candidatoService.findById(1L);
        assertEquals("Test Candidato", result.getNome());
    }

    @Test
    @DisplayName("Deve salvar candidato com sucesso quando CPF não existe")
    void testSaveCandidatoComSucesso() {
        Candidato candidato = new Candidato();
        candidato.setNome("João");
        candidato.setCpf("12345678900");

        when(candidatoRepository.findByCpfContaining("12345678900"))
                .thenReturn(Collections.emptyList());

        String result = candidatoService.save(candidato);

        assertEquals("o Candidato João foi salvo com sucesso", result);
        verify(candidatoRepository, times(1)).save(candidato);
    }

    @Test
    @DisplayName("Deve deletar candidato com sucesso")
    void testDelete() {
        String msg = candidatoService.delete(10L);
        assertEquals("O Candidato foi deletado", msg);
        verify(candidatoRepository).deleteById(10L);
    }

    @Test
    @DisplayName("Deve atualizar candidato com sucesso e atribuir ID")
    void testUpdate() {
        Candidato candidato = new Candidato();
        candidato.setNome("Ana");

        String result = candidatoService.update(candidato, 5L);

        assertEquals("Ana foi atualizado com sucesso!", result);
        assertEquals(5L, candidato.getId());
        verify(candidatoRepository).save(candidato);
    }

    @Test
    @DisplayName("Deve retornar todos os candidatos com sucesso")
    void testFindAll() {
        Candidato c1 = new Candidato();
        c1.setNome("C1");
        Candidato c2 = new Candidato();
        c2.setNome("C2");

        List<Candidato> mockList = Arrays.asList(c1, c2);
        when(candidatoRepository.findAll()).thenReturn(mockList);

        List<Candidato> result = candidatoService.findAll();

        assertEquals(2, result.size());
        assertEquals("C1", result.get(0).getNome());
    }

    @Test
    @DisplayName("Deve encontrar candidato por CPF contendo parte do número")
    void testFindByCpfContaining() {
        Candidato c = new Candidato();
        c.setCpf("99999999999");

        when(candidatoRepository.findByCpfContaining("999"))
                .thenReturn(Collections.singletonList(c));

        List<Candidato> result = candidatoService.findByCpfContaining("999");

        assertEquals(1, result.size());
        assertEquals("99999999999", result.get(0).getCpf());
    }

    @Test
    @DisplayName("Deve realizar inscrição de candidato com sucesso")
    void testInscricao() {
        String msg = candidatoService.inscricao(1L, 2L);
        assertEquals("inscricao realizada com sucesso", msg);
        verify(candidatoRepository).inscricao(1L, 2L);
    }*/
}
