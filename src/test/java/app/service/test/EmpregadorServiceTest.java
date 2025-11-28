package app.service.test;

import app.entity.Empregador;
import app.entity.Endereco;
import app.repository.EmpregadorRepository;
import app.repository.EnderecoRepository;
import app.service.EmpregadorService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EmpregadorServiceTest {

    @Mock
    private EmpregadorRepository empregadorRepository;

    @Mock
    private EnderecoRepository enderecoRepository;

    @InjectMocks
    private EmpregadorService empregadorService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

   /* @Test
    @DisplayName("Deve salvar empregador com sucesso quando CNPJ não existe")
    void testSaveEmpregadorComSucesso() {
        Empregador empregador = new Empregador();
        empregador.setNomeFantasia("Empresa X");
        empregador.setCnpj("12345678000195");

        when(empregadorRepository.findByCnpjContaining("12345678000195"))
                .thenReturn(Collections.emptyList());

        String resultado = empregadorService.save(empregador);

        assertEquals("o Empregador Empresa X de CNPJ: 12345678000195 foi salvo com sucesso", resultado);
        verify(empregadorRepository).save(empregador);
    }

    @Test
    @DisplayName("Deve lançar exceção ao tentar salvar empregador com CNPJ duplicado")
    void testSaveEmpregadorCnpjDuplicado() {
        Empregador existente = new Empregador();
        existente.setCnpj("11111111000111");

        Empregador novo = new Empregador();
        novo.setCnpj("11111111000111");

        when(empregadorRepository.findByCnpjContaining("11111111000111"))
                .thenReturn(List.of(existente));

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            empregadorService.save(novo);
        });

        assertEquals("Ja existe um empregador cadastrado com o 11111111000111", ex.getMessage());
        verify(empregadorRepository, never()).save(any());
    }

    @Test
    @DisplayName("Deve encontrar empregador por ID com sucesso")
    void testFindById() {
        Empregador emp = new Empregador();
        emp.setId(1L);
        emp.setNomeFantasia("Buscado");

        when(empregadorRepository.findById(1L)).thenReturn(Optional.of(emp));

        Empregador resultado = empregadorService.findById(1L);

        assertEquals("Buscado", resultado.getNomeFantasia());
    }

    @Test
    @DisplayName("Deve atualizar empregador e atribuir ID corretamente")
    void testUpdateEmpregador() {
        Empregador emp = new Empregador();
        emp.setNomeFantasia("Atualizado");

        String resposta = empregadorService.update(emp, 3L);

        assertEquals("Atualizado foi atualizado com sucesso!", resposta);
        assertEquals(3L, emp.getId());
        verify(empregadorRepository).save(emp);
    }

    @Test
    @DisplayName("Deve retornar todos os empregadores")
    void testFindAll() {
        Empregador e1 = new Empregador(); e1.setNomeFantasia("A");
        Empregador e2 = new Empregador(); e2.setNomeFantasia("B");

        when(empregadorRepository.findAll()).thenReturn(Arrays.asList(e1, e2));

        List<Empregador> lista = empregadorService.findAll();

        assertEquals(2, lista.size());
        assertEquals("A", lista.get(0).getNomeFantasia());
    }

    @Test
    @DisplayName("Deve deletar empregador com sucesso")
    void testDelete() {
        String resposta = empregadorService.delete(10L);

        assertEquals("O Empregador foi deletado", resposta);
        verify(empregadorRepository).deleteById(10L);
    }

    @Test
    @DisplayName("Deve buscar empregador por nome fantasia")
    void testFindByNomeFantasia() {
        Empregador e = new Empregador(); e.setNomeFantasia("Empresa XP");

        when(empregadorRepository.findByNomeFantasia("Empresa XP"))
                .thenReturn(List.of(e));

        List<Empregador> resultado = empregadorService.findByNomeFantasia("Empresa XP");

        assertEquals(1, resultado.size());
        assertEquals("Empresa XP", resultado.get(0).getNomeFantasia());
    }

    @Test
    @DisplayName("Deve buscar empregadores cujo nome fantasia contenha parte da string")
    void testFindByNomeFantasiaContaining() {
        Empregador e = new Empregador(); e.setNomeFantasia("Tech Solutions");

        when(empregadorRepository.findByNomeFantasiaContaining("Tech"))
                .thenReturn(List.of(e));

        List<Empregador> resultado = empregadorService.findByNomeFantasiaContaining("Tech");

        assertEquals(1, resultado.size());
        assertTrue(resultado.get(0).getNomeFantasia().contains("Tech"));
    }

    @Test
    @DisplayName("Deve buscar empregadores cujo CNPJ contenha parte da string")
    void testFindByCnpjContaining() {
        Empregador e = new Empregador(); e.setCnpj("12345678000195");

        when(empregadorRepository.findByCnpjContaining("123"))
                .thenReturn(List.of(e));

        List<Empregador> resultado = empregadorService.findByCnpjContaining("123");

        assertEquals(1, resultado.size());
        assertTrue(resultado.get(0).getCnpj().contains("123"));
    }

    @Test
    @DisplayName("Deve salvar empregador com endereços e associar corretamente")
    void testSaveEmpregadorComEnderecos() {
        Empregador empregador = new Empregador();
        empregador.setCnpj("55555555000155");
        empregador.setNomeFantasia("Empresa Endereçada");

        Endereco endereco = new Endereco();
        List<Endereco> enderecos = List.of(endereco);
        empregador.setEnderecos(enderecos);

        when(empregadorRepository.findByCnpjContaining("55555555000155"))
                .thenReturn(Collections.emptyList());

        String resultado = empregadorService.save(empregador);

        assertEquals("o Empregador Empresa Endereçada de CNPJ: 55555555000155 foi salvo com sucesso", resultado);
        assertEquals(empregador, endereco.getEmpregador());
        verify(empregadorRepository).save(empregador);
    }*/
}
