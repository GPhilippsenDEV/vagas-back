package app.controller.test;

import app.controller.VagasController;
import app.entity.Vagas;
import app.service.VagasService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class VagasControllerTest {

    @Autowired
    private VagasController vagasController;

    @MockitoBean
    private VagasService vagasService;

   /* @Test
    @DisplayName("Deve salvar uma vaga e retornar mensagem de sucesso com status 200")
    void cenarioSaveVaga() {
        Vagas vaga = new Vagas();
        vaga.setDescricao("Java Dev");

        when(vagasService.save(vaga)).thenReturn("a Vaga Java Dev foi salvo com sucesso");

        ResponseEntity<String> resposta = vagasController.save(vaga);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("a Vaga Java Dev foi salvo com sucesso", resposta.getBody());
        verify(vagasService).save(vaga);
    }

    @Test
    @DisplayName("Deve deletar uma vaga e retornar mensagem de sucesso com status 200")
    void cenarioDeleteVaga() {
        long id = 1L;
        when(vagasService.delete(id)).thenReturn("A Vaga foi deletado");

        ResponseEntity<String> resposta = vagasController.delete(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("A Vaga foi deletado", resposta.getBody());
        verify(vagasService).delete(id);
    }

    @Test
    @DisplayName("Deve buscar uma vaga por ID e retornar com status 200")
    void cenarioFindById() {
        long id = 2L;
        Vagas vaga = new Vagas();
        vaga.setId(id);
        vaga.setDescricao("DevOps");

        when(vagasService.findById(id)).thenReturn(vaga);

        ResponseEntity<Vagas> resposta = vagasController.findById(id);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("DevOps", resposta.getBody().getDescricao());
        verify(vagasService).findById(id);
    }

    @Test
    @DisplayName("Deve atualizar uma vaga e retornar mensagem de sucesso com status 200")
    void cenarioUpdateVaga() {
        long id = 3L;
        Vagas vaga = new Vagas();
        vaga.setDescricao("Atualizada");

        when(vagasService.update(vaga, id)).thenReturn("Atualizada foi atualizado com sucesso!");

        ResponseEntity<String> resposta = vagasController.update(id, vaga);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("Atualizada foi atualizado com sucesso!", resposta.getBody());
        verify(vagasService).update(vaga, id);
    }

    @Test
    @DisplayName("Deve retornar todas as vagas com status 200")
    void cenarioFindAll() {
        Vagas v1 = new Vagas(); v1.setDescricao("Front");
        Vagas v2 = new Vagas(); v2.setDescricao("Back");

        when(vagasService.findAll()).thenReturn(Arrays.asList(v1, v2));

        ResponseEntity<List<Vagas>> resposta = vagasController.findAll();

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals(2, resposta.getBody().size());
        verify(vagasService).findAll();
    }

    @Test
    @DisplayName("Deve buscar vagas por título ignorando case e retornar com status 200")
    void cenarioFindByTitulo() {
        String titulo = "java";
        Vagas v = new Vagas(); v.setDescricao("java backend");

        when(vagasService.findByTituloContainingIgnoreCase(titulo)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findByTituloContainingIgnoreCase(titulo);

        assertEquals(200, resposta.getStatusCodeValue());
        assertTrue(resposta.getBody().get(0).getDescricao().contains("java"));
    }

    @Test
    @DisplayName("Deve buscar vagas por requisito e retornar com status 200")
    void cenarioFindByRequisito() {
        String requisito = "spring";
        Vagas v = new Vagas(); v.setDescricao("vaga com spring");

        when(vagasService.findByRequisito(requisito)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findByRequisito(requisito);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga com spring", resposta.getBody().get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas com salário entre dois valores e retornar com status 200")
    void cenarioFindBySalarioBetween() {
        float salario1 = 2000f;
        float salario2 = 4000f;
        Vagas v = new Vagas(); v.setDescricao("vaga 3k");

        when(vagasService.findBySalarioBetween(salario1, salario2)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findBySalarioBetween(salario1, salario2);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga 3k", resposta.getBody().get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por setor e retornar com status 200")
    void cenarioFindBySetor() {
        String setor = "TI";
        Vagas v = new Vagas(); v.setDescricao("vaga TI");

        when(vagasService.findBySetor(setor)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findBySetor(setor);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga TI", resposta.getBody().get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas pela data de anúncio e retornar com status 200")
    void cenarioFindByDataAnuncio() {
        LocalDate data = LocalDate.now();
        Vagas v = new Vagas(); v.setDescricao("vaga hoje");

        when(vagasService.findByDataAnuncio(data)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findByDataAnuncio(data);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga hoje", resposta.getBody().get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por tipo de contratação e retornar com status 200")
    void cenarioFindByTipo() {
        String tipo = "CLT";
        Vagas v = new Vagas(); v.setDescricao("vaga CLT");

        when(vagasService.findByTipo(tipo)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findByTipo(tipo);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga CLT", resposta.getBody().get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por nível de experiência e retornar com status 200")
    void cenarioFindByNivelExperiencia() {
        String nivel = "junior";
        Vagas v = new Vagas(); v.setDescricao("vaga junior");

        when(vagasService.findByNivelExperiencia(nivel)).thenReturn(List.of(v));

        ResponseEntity<List<Vagas>> resposta = vagasController.findByNivelExperiencia(nivel);

        assertEquals(200, resposta.getStatusCodeValue());
        assertEquals("vaga junior", resposta.getBody().get(0).getDescricao());
    }*/
}

