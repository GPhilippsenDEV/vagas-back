package app.controller.test;

import app.controller.EnderecoController;
import app.entity.Endereco;
import app.service.EnderecoService;

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
class EnderecoControllerTest {

    @Autowired
    private EnderecoController enderecoController;

    @MockitoBean
    private EnderecoService enderecoService;

  /*  @Test
    @DisplayName("Deve salvar um endereço e retornar mensagem de sucesso com status 200")
    void cenarioSaveEndereco() {
        Endereco endereco = new Endereco();
        endereco.setCidade("São Paulo");

        when(enderecoService.save(endereco)).thenReturn("Endereço salvo com sucesso");

        ResponseEntity<String> resposta = enderecoController.save(endereco);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Endereço salvo com sucesso", resposta.getBody());
        verify(enderecoService).save(endereco);
    }

    @Test
    @DisplayName("Deve deletar endereço e retornar mensagem de sucesso com status 200")
    void cenarioDeleteEndereco() {
        long id = 1L;
        when(enderecoService.delete(id)).thenReturn("Endereço deletado");

        ResponseEntity<String> resposta = enderecoController.delete(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Endereço deletado", resposta.getBody());
        verify(enderecoService).delete(id);
    }

    @Test
    @DisplayName("Deve buscar endereço pelo ID e retornar com status 200")
    void cenarioFindByIdEndereco() {
        long id = 2L;
        Endereco endereco = new Endereco();
        endereco.setId(id);
        endereco.setCidade("Recife");

        when(enderecoService.findById(id)).thenReturn(endereco);

        ResponseEntity<Endereco> resposta = enderecoController.findById(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Recife", resposta.getBody().getCidade());
        verify(enderecoService).findById(id);
    }

    @Test
    @DisplayName("Deve atualizar um endereço e retornar mensagem de sucesso com status 200")
    void cenarioUpdateEndereco() {
        long id = 3L;
        Endereco endereco = new Endereco();
        endereco.setCidade("Curitiba");

        when(enderecoService.update(endereco, id)).thenReturn("Atualizado com sucesso");

        ResponseEntity<String> resposta = enderecoController.update(id, endereco);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Atualizado com sucesso", resposta.getBody());
        verify(enderecoService).update(endereco, id);
    }

    @Test
    @DisplayName("Deve retornar todos os endereços com status 200")
    void cenarioFindAllEnderecos() {
        Endereco e1 = new Endereco(); e1.setCidade("Rio");
        Endereco e2 = new Endereco(); e2.setCidade("SP");

        when(enderecoService.findAll()).thenReturn(Arrays.asList(e1, e2));

        ResponseEntity<List<Endereco>> resposta = enderecoController.findAll();

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals(2, resposta.getBody().size());
        verify(enderecoService).findAll();
    }

    @Test
    @DisplayName("Deve buscar endereço por cidade exata e retornar com status 200")
    void cenarioFindByCidade() {
        Endereco endereco = new Endereco();
        endereco.setCidade("Salvador");

        when(enderecoService.findByCidade("Salvador")).thenReturn(List.of(endereco));

        ResponseEntity<List<Endereco>> resposta = enderecoController.findByCidade("Salvador");

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Salvador", resposta.getBody().get(0).getCidade());
        verify(enderecoService).findByCidade("Salvador");
    }

    @Test
    @DisplayName("Deve buscar endereços por estado exato e retornar com status 200")
    void cenarioFindByEstado() {
        Endereco endereco = new Endereco();
        endereco.setEstado("BA");

        when(enderecoService.findByEstado("BA")).thenReturn(List.of(endereco));

        ResponseEntity<List<Endereco>> resposta = enderecoController.findByEstado("BA");

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("BA", resposta.getBody().get(0).getEstado());
        verify(enderecoService).findByEstado("BA");
    }

    @Test
    @DisplayName("Deve buscar endereços contendo parte do nome da cidade e retornar com status 200")
    void cenarioFindByCidadeContaining() {
        Endereco endereco = new Endereco();
        endereco.setCidade("Porto Alegre");

        when(enderecoService.findByCidadeContaining("Porto")).thenReturn(List.of(endereco));

        ResponseEntity<List<Endereco>> resposta = enderecoController.findByCidadeContaining("Porto");

        assertEquals(200, resposta.getStatusCodeValue());
        assertTrue(resposta.getBody().get(0).getCidade().contains("Porto"));
        verify(enderecoService).findByCidadeContaining("Porto");
    }

    @Test
    @DisplayName("Deve buscar endereços contendo parte do estado e retornar com status 200")
    void cenarioFindByEstadoContaining() {
        Endereco endereco = new Endereco();
        endereco.setEstado("RS");

        when(enderecoService.findByEstadoContaining("R")).thenReturn(List.of(endereco));

        ResponseEntity<List<Endereco>> resposta = enderecoController.findByEstadoContaining("R");

        assertEquals(200, resposta.getStatusCodeValue());
        assertTrue(resposta.getBody().get(0).getEstado().contains("R"));
        verify(enderecoService).findByEstadoContaining("R");
    }*/
}
