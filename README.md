# Zip Cracker — Leitor / Decodificador de senhas de arquivos .zip

**Resumo:**  
Aplicação GUI (Tkinter + ttkbootstrap) que realiza ataques por força bruta baseados em *wordlists* para descobrir a senha de arquivos `.zip` (AES/ZIP). Projeto educacional — use **apenas** em arquivos que você possui ou tem permissão explícita para testar.

---

# Funcionalidade & visão geral

O objetivo do projeto é demonstrar conceitos práticos de *brute-force* e paralelismo em Python aplicados a arquivos ZIP:

- **Análise do ZIP:** lista entradas internas, tamanhos e detecta se há bits de encriptação.
- **Ataque por wordlist:** lê um arquivo `.txt` com possíveis senhas, gera variantes simples (ex.: `word`, `Word`, `WORD`, `word.strip()`) e tenta abrir o ZIP usando cada candidata.
- **Paralelismo com threads:** utiliza `concurrent.futures.ThreadPoolExecutor` para subir várias tentativas simultâneas, cada thread abrindo sua própria instância do arquivo ZIP (via `pyzipper`).
- **Controle de carga:** limite de "max pendentes" para não esgotar memória; envio de mensagens para UI via `queue.Queue`.
- **UI responsiva:** Tkinter + ttkbootstrap para acompanhar progresso, tentativas por segundo, tempo decorrido e log em tempo real.
- **Segurança e ética:** aviso explícito para uso educacional/legítimo.

---

# Principais componentes

- `app.py` — aplicação principal com GUI (abrir ZIP, selecionar wordlist, configurar workers, iniciar/parar ataque).
- Funções úteis:
  - `analyze_zip(path)` — retorna entradas e flag de encriptação.
  - `stream_wordlist(path)` — gera senhas linha-a-linha (streaming).
  - `generate_variants(word)` — gera variantes simples de uma palavra.
  - `attack_worker_parallel(...)` — orquestra o pool de threads, envia mensagens para UI, trata resultados.

---

# Requisitos / Dependências

- Python 3.8+ (recomendado 3.10/3.11)
- Pip

Bibliotecas Python (instalar via `pip`):

- `pyzipper` — leitura/extração de ZIPs com suporte AES e senhas.
- `ttkbootstrap` — tema moderno para Tkinter.
- (opcionais — já parte da stdlib) `tkinter`, `concurrent.futures`, `queue`, `threading`, `zipfile`.

Arquivo de exemplo `requirements.txt`:

```
pyzipper>=0.3.7
ttkbootstrap>=1.6.0
```

> Observação: no Linux pode ser necessário instalar pacotes do sistema para suporte ao Tk (ex.: `sudo apt install python3-tk`).

---

# Como baixar / clonar o projeto

```bash
# clonar repositório (exemplo)
git clone https://github.com/SEU_USUARIO/zip-cracker.git
cd zip-cracker
```

Se você recebeu apenas o arquivo `app.py`, coloque-o dentro de uma pasta de projeto.

---

# Instalação (recomendado: ambiente virtual)

```bash
# criar e ativar virtualenv (Unix/macOS)
python -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# instalar dependências
pip install -r requirements.txt
```

Se não tiver `requirements.txt`, instale manualmente:

```bash
pip install pyzipper ttkbootstrap
```

---

# Como executar

1. Execute a aplicação:

```bash
python app.py
```

2. Na interface:
   - Clique em **Abrir** para selecionar o arquivo `.zip`.
   - Clique em **Abrir** (em Wordlist) para selecionar um `.txt` com possíveis senhas (uma por linha).
   - Configure **Workers (threads)** e **Max pendentes** conforme sua máquina.
   - Pressione **Start** para iniciar. Use **Stop** para cancelar a qualquer momento.
   - Logs e status aparecem em tempo real (tentativas, t/s, tempo, encontrado/terminado).

---

# Parâmetros importantes

- **Workers (threads):** número de threads que tentarão senhas em paralelo. Aumentar melhora a taxa de tentativas até o limite I/O/CPU da máquina.
- **Max pendentes:** número máximo de tarefas enfileiradas no executor. Evita consumo excessivo de memória ao gerar muitas variantes.
- **Wordlist:** qualidade da wordlist é decisiva — prefira listas direcionadas (palavras relacionadas ao alvo, combinações comuns, sufixos de anos, etc.).

---

# Algoritmo (resumido)

1. Abre o `.zip` para listar um arquivo de teste (primeiro item) para a tentativa de leitura.
2. Para cada linha da wordlist:
   - Gera variantes simples (capitalização, trim, lower/upper).
   - Submete cada variante como tarefa ao `ThreadPoolExecutor`.
3. Cada tarefa:
   - Abre a própria instância do `.zip` (via `pyzipper`), define `zf.pwd` com a senha candidata e tenta ler o arquivo de teste.
   - Se a leitura for bem-sucedida, envia mensagem de `found` e sinaliza `stop_event`.
4. A função principal do worker monitora `futures`, limpa finalizados e envia mensagens de progresso para a UI via `queue`.

---

# Boas práticas & considerações

- **Ética:** nunca use contra arquivos que você não tenha permissão. Uso não autorizado é ilegal.
- **Performance:** testes em SSDs e com wordlists em disco local são muito mais rápidos que em NFS/HDs lentos.
- **Memória:** cuidado com `max_pending` e número de variantes por palavra — podem explodir combinacionalmente.
- **Codificação:** o leitor de wordlist usa `errors='ignore'` para evitar travamentos com encodings estranhos.
- **ZIPs modernos:** alguns ZIPs usam métodos/formatos que podem não ser suportados por todas as bibliotecas — `pyzipper` cobre a maioria dos casos de AES.

---

# Mensagens / Logs

A aplicação registra no painel de log:
- cada tentativa (senha testada, t/s, tempo)
- quando a senha é encontrada (`>>> SENHA ENCONTRADA: ...`)
- finalização sem sucesso (tentativas e tempo)
- erros e cancelamentos

Você pode **Salvar Log** para auditoria.

---

# Problemas comuns & solução

- **Erro: `ModuleNotFoundError: No module named 'pyzipper'`**  
  → `pip install pyzipper`

- **Tkinter não encontrado (Linux)**  
  → `sudo apt install python3-tk` (ou pacote equivalente para sua distro)

- **Wordlist muito grande / queda de performance**  
  → aumentar `max_pendentes` com cuidado, reduzir `workers` ou usar wordlists segmentadas; implementar *resume*/checkpoint.

- **ZIP indicado como corrompido**  
  → confirme integridade do arquivo (ex.: `unzip -t file.zip`), certifique-se que é um `.zip` válido.

---

# Extensões sugeridas (futuras)

- Regras avançadas (leet speak, sufixos/affixes, combinações).
- Checkpoint/resume na wordlist (salvar posição atual).
- Suporte a múltiplas wordlists e priorização.
- Exportar estatísticas (CSV) e gráficos (matplotlib).
- Versão CLI para execução headless em servidores.

---