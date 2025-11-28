package app.controller.test;

import app.controller.CandidatoController;
import app.entity.Candidato;
import app.service.CandidatoService_;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class CandidatoControllerTest {

    @Autowired
    CandidatoController candidatoController;

    @MockitoBean
    CandidatoService_ candidatoService;

   /* @Test
    @DisplayName("Deve salvar o candidato e retornar mensagem de sucesso com status 200")
    void cenarioSaveCandidato() {
        Candidato candidato = new Candidato();
        candidato.setNome("João");

        when(candidatoService.save(candidato)).thenReturn("o Candidato João foi salvo com sucesso");

        ResponseEntity<String> resposta = candidatoController.save(candidato);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("o Candidato João foi salvo com sucesso", resposta.getBody());
        verify(candidatoService).save(candidato);
    }

    @Test
    @DisplayName("Deve deletar o candidato pelo ID e retornar mensagem de sucesso com status 200")
    void cenarioDeleteCandidato() {
        long id = 1L;
        when(candidatoService.delete(id)).thenReturn("O Candidato foi deletado");

        ResponseEntity<String> resposta = candidatoController.delete(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("O Candidato foi deletado", resposta.getBody());
        verify(candidatoService).delete(id);
    }

    @Test
    @DisplayName("Deve retornar o candidato pelo ID com status 200")
    void cenarioFindByIdCandidato() {
        long id = 1L;
        Candidato candidato = new Candidato();
        candidato.setId(id);
        candidato.setNome("Maria");

        when(candidatoService.findById(id)).thenReturn(candidato);

        ResponseEntity<Candidato> resposta = candidatoController.findById(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Maria", resposta.getBody().getNome());
        verify(candidatoService).findById(id);
    }

    @Test
    @DisplayName("Deve atualizar o candidato e retornar mensagem de sucesso com status 200")
    void cenarioUpdateCandidato() {
        long id = 2L;
        Candidato candidato = new Candidato();
        candidato.setNome("Carlos");

        when(candidatoService.update(candidato, id)).thenReturn("Carlos foi atualizado com sucesso!");

        ResponseEntity<String> resposta = candidatoController.update(id, candidato);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Carlos foi atualizado com sucesso!", resposta.getBody());
        verify(candidatoService).update(candidato, id);
    }

    @Test
    @DisplayName("Deve retornar a lista de todos os candidatos com status 200")
    void cenarioFindAllCandidatos() {
        Candidato c1 = new Candidato(); c1.setNome("A");
        Candidato c2 = new Candidato(); c2.setNome("B");

        when(candidatoService.findAll()).thenReturn(Arrays.asList(c1, c2));

        ResponseEntity<List<Candidato>> resposta = candidatoController.findAll();

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals(2, resposta.getBody().size());
        verify(candidatoService).findAll();
    }

    @Test
    @DisplayName("Deve realizar a inscrição do candidato em uma vaga com status 200")
    void cenarioInscricaoCandidato() {
        long idCandidato = 1L;
        long idVaga = 2L;

        when(candidatoService.inscricao(idCandidato, idVaga)).thenReturn("inscricao realizada com sucesso");

        ResponseEntity<String> resposta = candidatoController.inscricao(idCandidato, idVaga);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("inscricao realizada com sucesso", resposta.getBody());
        verify(candidatoService).inscricao(idCandidato, idVaga);
    }

    @Test
    @DisplayName("Deve retornar candidatos cujo CPF contenha a sequência informada")
    void cenarioFindByCpfContaining() {
        String cpf = "123";
        Candidato c = new Candidato();
        c.setCpf("12345678900");

        when(candidatoService.findByCpfContaining(cpf)).thenReturn(List.of(c));

        List<Candidato> resultado = candidatoController.findByCpfContaining(cpf);

        assertEquals(1, resultado.size());
        assertEquals("12345678900", resultado.get(0).getCpf());
        verify(candidatoService).findByCpfContaining(cpf);
    }*/
}
