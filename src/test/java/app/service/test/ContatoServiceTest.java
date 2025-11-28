package app.service.test;

import app.entity.Contato;
import app.repository.ContatoRepository;
import app.service.ContatoService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ContatoServiceTest {

    @Mock
    private ContatoRepository contatoRepository;

    @InjectMocks
    private ContatoService contatoService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

   /* @Test
    @DisplayName("Deve salvar contato com sucesso quando email não existe")
    void testSaveContatoComSucesso() {
        Contato novoContato = new Contato();
        novoContato.setEmail("novo@email.com");

        when(contatoRepository.findByEmail("novo@email.com")).thenReturn(null);

        String resposta = contatoService.save(novoContato);

        assertEquals("o Contato novo@email.com foi salvo com sucesso", resposta);
        verify(contatoRepository).save(novoContato);
    }

    @Test
    @DisplayName("Deve lançar exceção ao tentar salvar contato com email já existente")
    void testSaveContatoEmailJaExiste() {
        Contato contato = new Contato();
        contato.setEmail("existente@email.com");

        Contato existente = new Contato();
        existente.setEmail("existente@email.com");

        when(contatoRepository.findByEmail("existente@email.com")).thenReturn(existente);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            contatoService.save(contato);
        });

        assertEquals("Ja existe um contato cadastrado com o existente@email.com", ex.getMessage());
        verify(contatoRepository, never()).save(any());
    }

    @Test
    @DisplayName("Deve encontrar contato por ID com sucesso")
    void testFindById() {
        Contato contato = new Contato();
        contato.setId(1L);
        contato.setEmail("buscar@email.com");

        when(contatoRepository.findById(1L)).thenReturn(Optional.of(contato));

        Contato resultado = contatoService.findById(1L);

        assertNotNull(resultado);
        assertEquals("buscar@email.com", resultado.getEmail());
    }

    @Test
    @DisplayName("Deve atualizar contato com sucesso e atribuir ID")
    void testUpdateContato() {
        Contato contato = new Contato();
        contato.setEmail("atualizar@email.com");

        String resposta = contatoService.update(contato, 10L);

        assertEquals("atualizar@email.com foi atualizado com sucesso!", resposta);
        assertEquals(10L, contato.getId());
        verify(contatoRepository).save(contato);
    }

    @Test
    @DisplayName("Deve retornar todos os contatos")
    void testFindAll() {
        Contato c1 = new Contato(); c1.setEmail("a@email.com");
        Contato c2 = new Contato(); c2.setEmail("b@email.com");

        when(contatoRepository.findAll()).thenReturn(Arrays.asList(c1, c2));

        List<Contato> lista = contatoService.findAll();

        assertEquals(2, lista.size());
        assertEquals("a@email.com", lista.get(0).getEmail());
    }

    @Test
    @DisplayName("Deve deletar contato com sucesso")
    void testDeleteContato() {
        String resposta = contatoService.delete(5L);

        assertEquals("O Contato foi deletado", resposta);
        verify(contatoRepository).deleteById(5L);
    }*/
}
