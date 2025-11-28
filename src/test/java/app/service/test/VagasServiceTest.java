package app.service.test;

import app.entity.Vagas;
import app.repository.VagasRepository;
import app.service.VagasService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VagasServiceTest {

    @Mock
    private VagasRepository vagasRepository;

    @InjectMocks
    private VagasService vagasService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

  /*  @Test
    @DisplayName("Deve salvar uma vaga com sucesso")
    void testSaveVaga() {
        Vagas vaga = new Vagas();
        vaga.setDescricao("Desenvolvedor Java");

        when(vagasRepository.save(vaga)).thenReturn(vaga);

        String resultado = vagasService.save(vaga);

        assertEquals("a Vaga Desenvolvedor Java foi salvo com sucesso", resultado);
        verify(vagasRepository).save(vaga);
    }

    @Test
    @DisplayName("Deve buscar vaga por ID com sucesso")
    void testFindById() {
        Vagas vaga = new Vagas();
        vaga.setId(1L);
        vaga.setDescricao("Front-end");

        when(vagasRepository.findById(1L)).thenReturn(Optional.of(vaga));

        Vagas resultado = vagasService.findById(1L);

        assertNotNull(resultado);
        assertEquals("Front-end", resultado.getDescricao());
    }

    @Test
    @DisplayName("Deve atualizar uma vaga e atribuir o ID")
    void testUpdateVaga() {
        Vagas vaga = new Vagas();
        vaga.setDescricao("Atualizada");

        String resposta = vagasService.update(vaga, 5L);

        assertEquals("Atualizada foi atualizado com sucesso!", resposta);
        assertEquals(5L, vaga.getId());
        verify(vagasRepository).save(vaga);
    }

    @Test
    @DisplayName("Deve listar todas as vagas")
    void testFindAll() {
        Vagas v1 = new Vagas(); v1.setDescricao("QA");
        Vagas v2 = new Vagas(); v2.setDescricao("DevOps");

        when(vagasRepository.findAll()).thenReturn(Arrays.asList(v1, v2));

        List<Vagas> resultado = vagasService.findAll();

        assertEquals(2, resultado.size());
        assertEquals("QA", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve deletar vaga por ID")
    void testDelete() {
        String resultado = vagasService.delete(10L);

        assertEquals("A Vaga foi deletado", resultado);
        verify(vagasRepository).deleteById(10L);
    }

    @Test
    @DisplayName("Deve buscar vagas pelo título ignorando case")
    void testFindByTituloContainingIgnoreCase() {
        Vagas v = new Vagas(); v.setDescricao("vaga java");

        when(vagasRepository.findByTituloContainingIgnoreCase("java")).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findByTituloContainingIgnoreCase("java");

        assertEquals(1, resultado.size());
        assertEquals("vaga java", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por requisito específico")
    void testFindByRequisito() {
        Vagas v = new Vagas(); v.setDescricao("vaga com Spring");

        when(vagasRepository.findByRequisito("Spring")).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findByRequisito("Spring");

        assertEquals(1, resultado.size());
        assertEquals("vaga com Spring", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas com salário entre faixa especificada")
    void testFindBySalarioBetween() {
        Vagas v = new Vagas(); v.setDescricao("vaga 3k");

        when(vagasRepository.findBySalarioBetween(2000f, 4000f)).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findBySalarioBetween(2000f, 4000f);

        assertEquals(1, resultado.size());
        assertEquals("vaga 3k", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por setor")
    void testFindBySetor() {
        Vagas v = new Vagas(); v.setDescricao("vaga TI");

        when(vagasRepository.findBySetor("TI")).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findBySetor("TI");

        assertEquals(1, resultado.size());
        assertEquals("vaga TI", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por data do anúncio")
    void testFindByDataAnuncio() {
        LocalDate hoje = LocalDate.now();
        Vagas v = new Vagas(); v.setDescricao("vaga hoje");

        when(vagasRepository.findByDataAnuncio(hoje)).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findByDataAnuncio(hoje);

        assertEquals(1, resultado.size());
        assertEquals("vaga hoje", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por tipo")
    void testFindByTipo() {
        Vagas v = new Vagas(); v.setDescricao("vaga CLT");

        when(vagasRepository.findByTipo("CLT")).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findByTipo("CLT");

        assertEquals(1, resultado.size());
        assertEquals("vaga CLT", resultado.get(0).getDescricao());
    }

    @Test
    @DisplayName("Deve buscar vagas por nível de experiência")
    void testFindByNivelExperiencia() {
        Vagas v = new Vagas(); v.setDescricao("vaga junior");

        when(vagasRepository.findByNivelExperiencia("junior")).thenReturn(List.of(v));

        List<Vagas> resultado = vagasService.findByNivelExperiencia("junior");

        assertEquals(1, resultado.size());
        assertEquals("vaga junior", resultado.get(0).getDescricao());
    }*/
}
