package app.controller.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import app.controller.ContatoController;
import app.entity.Contato;
import app.service.ContatoService;

@SpringBootTest
class ContatoControllerTest {

    @Autowired
    private ContatoController contatoController;

    @MockitoBean
    private ContatoService contatoService;

   /* @Test
    @DisplayName("Deve salvar um novo contato e retornar mensagem de sucesso com status 200")
    void cenarioSaveContato() {
        Contato contato = new Contato();
        contato.setEmail("joao@email.com");

        when(contatoService.save(contato)).thenReturn("o Contato joao@email.com foi salvo com sucesso");

        ResponseEntity<String> resposta = contatoController.save(contato);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("o Contato joao@email.com foi salvo com sucesso", resposta.getBody());
        verify(contatoService).save(contato);
    }

    @Test
    @DisplayName("Deve deletar um contato pelo ID e retornar mensagem de sucesso com status 200")
    void cenarioDeleteContato() {
        long id = 1L;
        when(contatoService.delete(id)).thenReturn("O Contato foi deletado");

        ResponseEntity<String> resposta = contatoController.delete(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("O Contato foi deletado", resposta.getBody());
        verify(contatoService).delete(id);
    }

    @Test
    @DisplayName("Deve retornar o contato pelo ID com status 200")
    void cenarioFindByIdContato() {
        long id = 2L;
        Contato contato = new Contato();
        contato.setId(id);
        contato.setEmail("teste@email.com");

        when(contatoService.findById(id)).thenReturn(contato);

        ResponseEntity<Contato> resposta = contatoController.findById(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("teste@email.com", resposta.getBody().getEmail());
        verify(contatoService).findById(id);
    }

    @Test
    @DisplayName("Deve atualizar um contato existente e retornar mensagem de sucesso com status 200")
    void cenarioUpdateContato() {
        long id = 3L;
        Contato contato = new Contato();
        contato.setEmail("atualizado@email.com");

        when(contatoService.update(contato, id)).thenReturn("atualizado@email.com foi atualizado com sucesso!");

        ResponseEntity<String> resposta = contatoController.update(id, contato);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("atualizado@email.com foi atualizado com sucesso!", resposta.getBody());
        verify(contatoService).update(contato, id);
    }

    @Test
    @DisplayName("Deve retornar a lista de todos os contatos com status 200")
    void cenarioFindAllContatos() {
        Contato c1 = new Contato(); c1.setEmail("um@email.com");
        Contato c2 = new Contato(); c2.setEmail("dois@email.com");

        when(contatoService.findAll()).thenReturn(Arrays.asList(c1, c2));

        ResponseEntity<List<Contato>> resposta = contatoController.findAll();

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals(2, resposta.getBody().size());
        assertEquals("um@email.com", resposta.getBody().get(0).getEmail());
        verify(contatoService).findAll();
    }*/
}