# app.py
"""
Zip Cracker - GUI (Tkinter + ttkbootstrap) com paralelismo.
Uso educacional: faça isso somente em arquivos que você possui/permissão.

Instalação:
pip install pyzipper ttkbootstrap
"""

import os
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
import zipfile
import pyzipper
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ------------------ Utilitários ZIP ------------------

def analyze_zip(path: str):
    """Retorna metadados do zip: lista de entradas e se detectou encriptação."""
    entries = []
    encryption_detected = False
    try:
        with pyzipper.AESZipFile(path, 'r') as zf:
            for info in zf.infolist():
                is_enc = bool(info.flag_bits & 0x1)
                entries.append({
                    'name': info.filename,
                    'file_size': info.file_size,
                    'compress_size': info.compress_size,
                    'is_encrypted': is_enc
                })
                if is_enc:
                    encryption_detected = True
    except zipfile.BadZipFile:
        raise RuntimeError("Arquivo ZIP inválido/corrompido.")
    except Exception as e:
        raise RuntimeError(f"Erro ao abrir ZIP: {e}")
    return {'entries': entries, 'encryption_detected': encryption_detected}

def try_password_once(zip_path: str, password: str, test_file: Optional[str] = None) -> bool:
    """Tenta ler um arquivo interno com a senha; retorna True se funcionou."""
    if password is None:
        return False
    try:
        pw_bytes = password.encode('utf-8')
        # cada thread abre sua própria instância do zip
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            zf.pwd = pw_bytes
            if not test_file:
                namelist = zf.namelist()
                if not namelist:
                    # zip vazio -> considerar 'vazio' como sucesso (pouco comum)
                    return True
                test_file = namelist[0]
            # leitura do arquivo de teste
            _ = zf.read(test_file)
        return True
    except RuntimeError:
        # pyzipper pode lançar RuntimeError para senha incorreta
        return False
    except zipfile.BadZipFile:
        # caso raro onde a leitura falha por arquivo corrompido
        return False
    except Exception:
        # qualquer outra exceção tratamos como falha na tentativa
        return False

# ------------------ Wordlist ------------------

def stream_wordlist(path: str, encoding='utf-8'):
    """Gera senhas linha a linha (streaming)."""
    with open(path, 'r', encoding=encoding, errors='ignore') as f:
        for line in f:
            pw = line.rstrip('\n\r')
            if pw:
                yield pw

def generate_variants(word: str):
    """Versões simples da palavra — expanda se quiser."""
    # você pode adicionar limites ou opções para não explodir combinações
    yield word
    yield word.strip()
    yield word.capitalize()
    yield word.lower()
    yield word.upper()

def count_lines_limited(path: str, limit: int = 5_000_000, encoding='utf-8'):
    """Conta linhas da wordlist até um limite (para evitar travar em arquivos enormes)."""
    count = 0
    try:
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            for _ in f:
                count += 1
                if count > limit:
                    return None  # sinaliza "muito grande"
    except Exception:
        return None
    return count

# ------------------ Worker paralelo ------------------

def attack_worker_parallel(zip_path: str, wordlist_path: str, msg_queue: queue.Queue,
                           stop_event: threading.Event, max_workers: int = 4, max_pending: int = 500,
                           total_candidates: Optional[int] = None):
    """
    Gerencia ThreadPoolExecutor para tentar senhas em paralelo.
    Envia mensagens para msg_queue com chaves:
      'type' : 'progress' | 'found' | 'finished' | 'error' | 'stopped'
    """
    start_time = time.time()
    attempts = 0
    attempts_lock = threading.Lock()
    found = False
    found_data = None
    sent_found = False

    try:
        # define arquivo de teste (primeiro item dentro do zip)
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            namelist = zf.namelist()
            test_file = namelist[0] if namelist else None

        # função executada em threads
        def task_try_pw(pw_candidate):
            nonlocal attempts, found, found_data
            if stop_event.is_set() or found:
                return {'ok': False}
            ok = try_password_once(zip_path, pw_candidate, test_file=test_file)
            with attempts_lock:
                attempts += 1
                this_attempt = attempts
            elapsed = time.time() - start_time
            speed = this_attempt / elapsed if elapsed > 0 else 0.0
            # envia progresso
            msg_queue.put({
                'type': 'progress',
                'attempts': this_attempt,
                'password': pw_candidate,
                'elapsed': elapsed,
                'speed': speed,
                'total': total_candidates
            })
            if ok:
                found = True
                found_data = {'password': pw_candidate, 'attempts': this_attempt, 'elapsed': elapsed}
                # sinaliza stop
                stop_event.set()
                return {'ok': True, **found_data}
            return {'ok': False}

        # executor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = set()
            # itera wordlist e submete variantes
            for raw_pw in stream_wordlist(wordlist_path):
                if stop_event.is_set():
                    break
                for variant in generate_variants(raw_pw):
                    if stop_event.is_set():
                        break
                    # controle para limitar quantidade pendente
                    while len(futures) >= max_pending and not stop_event.is_set():
                        done = {f for f in list(futures) if f.done()}
                        for d in done:
                            futures.discard(d)
                        time.sleep(0.01)
                    if stop_event.is_set():
                        break
                    fut = executor.submit(task_try_pw, variant)
                    futures.add(fut)
                if stop_event.is_set():
                    break

            # aguardando finalização dos futuros ou interrupção
            while futures:
                done = {f for f in list(futures) if f.done()}
                if not done:
                    if stop_event.is_set():
                        # tenta cancelar pendentes
                        for f in list(futures):
                            try:
                                f.cancel()
                            except Exception:
                                pass
                        break
                    time.sleep(0.05)
                    continue
                for f in done:
                    futures.discard(f)
                    try:
                        res = f.result()
                        if isinstance(res, dict) and res.get('ok') and not sent_found:
                            # envia found (apenas uma vez)
                            msg_queue.put({
                                'type': 'found',
                                'password': res.get('password'),
                                'attempts': res.get('attempts'),
                                'elapsed': res.get('elapsed')
                            })
                            sent_found = True
                            # cancela pendentes e finaliza
                            stop_event.set()
                            for other in list(futures):
                                try:
                                    other.cancel()
                                except Exception:
                                    pass
                            futures.clear()
                            break
                    except Exception:
                        # Ignorar exceções de tarefa individual
                        pass

        # depois do executor
        if sent_found and found_data:
            # já foi enviado 'found' dentro do loop; redundância evitada
            pass
        else:
            msg_queue.put({'type': 'finished', 'attempts': attempts, 'elapsed': time.time() - start_time})
    except Exception as e:
        msg_queue.put({'type': 'error', 'error': str(e), 'attempts': attempts})
    finally:
        if stop_event.is_set() and not sent_found:
            msg_queue.put({'type': 'stopped', 'attempts': attempts})

# ------------------ GUI ------------------

class ZipCrackerApp:
    def __init__(self, root: tb.Window):
        self.root = root
        self.root.title("Zip Cracker - Tkinter (ttkbootstrap)")
        self.msg_queue = queue.Queue()
        self.worker_thread = None
        self.stop_event = threading.Event()

        self._build_ui()
        # polling da fila
        self.root.after(100, self._poll_queue)

    def _build_ui(self):
        pad = 8
        frm_top = ttk.Frame(self.root)
        frm_top.pack(fill='x', padx=pad, pady=pad)

        # ZIP selector
        ttk.Label(frm_top, text="Arquivo .zip:").grid(row=0, column=0, sticky='w')
        self.zip_entry = ttk.Entry(frm_top, width=60)
        self.zip_entry.grid(row=0, column=1, padx=6)
        ttk.Button(frm_top, text="Abrir", command=self._browse_zip).grid(row=0, column=2)

        # Wordlist selector
        ttk.Label(frm_top, text="Wordlist (.txt):").grid(row=1, column=0, sticky='w', pady=(6,0))
        self.wl_entry = ttk.Entry(frm_top, width=60)
        self.wl_entry.grid(row=1, column=1, padx=6, pady=(6,0))
        ttk.Button(frm_top, text="Abrir", command=self._browse_wordlist).grid(row=1, column=2, pady=(6,0))

        # Workers and max pendentes (layout organizado)
        ttk.Label(frm_top, text="Workers (threads):").grid(row=2, column=0, sticky='w', pady=(6,0))
        self.workers_spin = ttk.Spinbox(frm_top, from_=1, to=64, increment=1, width=6)
        self.workers_spin.set(4)
        self.workers_spin.grid(row=2, column=1, sticky='w', pady=(6,0))

        ttk.Label(frm_top, text="Max pendentes:").grid(row=2, column=1, sticky='w', padx=(120,0))
        self.maxpend_entry = ttk.Entry(frm_top, width=8)
        self.maxpend_entry.insert(0, "500")
        self.maxpend_entry.grid(row=2, column=1, sticky='w', padx=(200,0))

        # ZIP entries (treeview)
        frm_mid = ttk.Frame(self.root)
        frm_mid.pack(fill='both', expand=True, padx=pad, pady=(0,pad))
        ttk.Label(frm_mid, text="Entradas do ZIP:").pack(anchor='w')
        columns = ('#1', '#2', '#3')
        self.tree = ttk.Treeview(frm_mid, columns=columns, show='headings', height=6)
        self.tree.heading('#1', text='Nome')
        self.tree.heading('#2', text='Tamanho')
        self.tree.heading('#3', text='Encrip.')
        self.tree.column('#1', width=400)
        self.tree.column('#2', width=100, anchor='e')
        self.tree.column('#3', width=60, anchor='center')
        self.tree.pack(fill='both', expand=True)

        # Status + progress
        frm_status = ttk.Frame(self.root)
        frm_status.pack(fill='x', padx=pad, pady=(0,pad))
        self.status_var = tk.StringVar(value='Pronto')
        ttk.Label(frm_status, text="Status:").grid(row=0, column=0, sticky='w')
        ttk.Label(frm_status, textvariable=self.status_var).grid(row=0, column=1, sticky='w')

        ttk.Label(frm_status, text="Tentativas:").grid(row=0, column=2, sticky='e')
        self.attempts_var = tk.StringVar(value='0')
        ttk.Label(frm_status, textvariable=self.attempts_var).grid(row=0, column=3, sticky='w', padx=(4,12))

        ttk.Label(frm_status, text="Velocidade (t/s):").grid(row=0, column=4, sticky='e')
        self.speed_var = tk.StringVar(value='0.0')
        ttk.Label(frm_status, textvariable=self.speed_var).grid(row=0, column=5, sticky='w', padx=(4,12))

        ttk.Label(frm_status, text="Tempo:").grid(row=0, column=6, sticky='e')
        self.elapsed_var = tk.StringVar(value='0.0s')
        ttk.Label(frm_status, textvariable=self.elapsed_var).grid(row=0, column=7, sticky='w', padx=(4,0))

        self.progress = ttk.Progressbar(self.root, orient='horizontal', length=600, mode='determinate')
        self.progress.pack(fill='x', padx=pad, pady=(0,pad))

        # Log
        ttk.Label(self.root, text="Log:").pack(anchor='w', padx=pad)
        self.log_text = scrolledtext.ScrolledText(self.root, height=12, state='disabled')
        self.log_text.pack(fill='both', expand=True, padx=pad, pady=(0,pad))

        # Buttons
        frm_buttons = ttk.Frame(self.root)
        frm_buttons.pack(fill='x', padx=pad, pady=(0,pad))
        self.start_btn = ttk.Button(frm_buttons, text="Start", bootstyle=SUCCESS, command=self.start_attack)
        self.start_btn.pack(side='left', padx=6)
        self.stop_btn = ttk.Button(frm_buttons, text="Stop", bootstyle='danger', command=self.stop_attack, state='disabled')
        self.stop_btn.pack(side='left', padx=6)
        self.clear_btn = ttk.Button(frm_buttons, text="Limpar Log", command=self.clear_log)
        self.clear_btn.pack(side='left', padx=6)
        self.save_btn = ttk.Button(frm_buttons, text="Salvar Log", command=self.save_log)
        self.save_btn.pack(side='left', padx=6)
        self.quit_btn = ttk.Button(frm_buttons, text="Sair", command=self._on_quit)
        self.quit_btn.pack(side='right', padx=6)

    # ------------------ Ações UI ------------------

    def _browse_zip(self):
        path = filedialog.askopenfilename(filetypes=[("ZIP Files", "*.zip")])
        if path:
            self.zip_entry.delete(0, tk.END)
            self.zip_entry.insert(0, path)
            # analisar zip e preencher treeview
            try:
                meta = analyze_zip(path)
                self.tree.delete(*self.tree.get_children())
                for e in meta['entries']:
                    enc = '🔒' if e.get('is_encrypted') else ''
                    self.tree.insert('', tk.END, values=(e.get('name'), f"{e.get('file_size')} B", enc))
                self.status_var.set(f"ZIP analisado. Encriptação detectada: {meta['encryption_detected']}")
            except Exception as ex:
                messagebox.showerror("Erro", f"Não foi possível analisar o ZIP:\n{ex}")
                self.status_var.set("Erro ao analisar ZIP")

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.wl_entry.delete(0, tk.END)
            self.wl_entry.insert(0, path)

    def _append_log(self, text):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.configure(state='disabled')

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files","*.txt")])
        if not path:
            return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.log_text.get('1.0', tk.END))
        messagebox.showinfo("Salvo", f"Log salvo em: {path}")

    def start_attack(self):
        zip_path = self.zip_entry.get().strip()
        wordlist_path = self.wl_entry.get().strip()
        try:
            workers = int(self.workers_spin.get())
        except Exception:
            messagebox.showerror("Erro", "Workers inválido")
            return
        try:
            maxpend = int(self.maxpend_entry.get())
        except Exception:
            messagebox.showerror("Erro", "Max pendentes inválido")
            return

        if not zip_path or not os.path.isfile(zip_path):
            messagebox.showerror("Erro", "Selecione um arquivo ZIP válido.")
            return
        if not wordlist_path or not os.path.isfile(wordlist_path):
            messagebox.showerror("Erro", "Selecione uma wordlist válida.")
            return

        # tenta contar linhas para saber se podemos mostrar progresso real
        total_lines = count_lines_limited(wordlist_path, limit=2_000_000)
        if total_lines is None:
            total_candidates = None
            self.progress.configure(mode='indeterminate')
            self.progress.start(10)
        else:
            # estimativa simples: total_lines * variantes_per_word (aqui 5)
            total_candidates = total_lines * 5
            self.progress.configure(mode='determinate', maximum=total_candidates)
            self.progress.stop()

        # reset UI
        self.clear_log()
        self.attempts_var.set('0')
        self.speed_var.set('0.0')
        self.elapsed_var.set('0.0s')
        if total_candidates is None:
            self.progress['value'] = 0
        else:
            self.progress['value'] = 0
        self.status_var.set('Ataque iniciado...')
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')

        # start thread que gerencia executor
        self.msg_queue = queue.Queue()
        self.stop_event.clear()
        self.worker_thread = threading.Thread(
            target=attack_worker_parallel,
            args=(zip_path, wordlist_path, self.msg_queue, self.stop_event, workers, maxpend, total_candidates),
            daemon=True
        )
        self.worker_thread.start()

    def stop_attack(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_event.set()
            self.status_var.set('Solicitado cancelamento...')
            self.stop_btn.configure(state='disabled')

    def _on_quit(self):
        if self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("Sair", "O ataque está em execução. Deseja parar e sair?"):
                return
            self.stop_event.set()
            self.worker_thread.join(timeout=1.0)
        self.root.destroy()

    # ------------------ Poll da fila de mensagens ------------------

    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                mtype = msg.get('type')
                if mtype == 'progress':
                    self.attempts_var.set(str(msg.get('attempts', 0)))
                    self.speed_var.set(f"{msg.get('speed', 0.0):.1f}")
                    self.elapsed_var.set(f"{msg.get('elapsed', 0.1):.1f}s")
                    total = msg.get('total')
                    attempts = msg.get('attempts', 0)
                    # progresso real se tivermos total
                    if total:
                        self.progress.configure(mode='determinate', maximum=total)
                        self.progress['value'] = min(attempts, total)
                    else:
                        # modo indeterminado simbólico: mostramos um valor circular
                        self.progress.configure(mode='indeterminate')
                    pw = msg.get('password', '')
                    self._append_log(f"[{msg.get('attempts')}] tentar: {pw}  ({msg.get('speed'):.1f} t/s, {msg.get('elapsed'):.1f}s)\n")
                elif mtype == 'found':
                    pw = msg.get('password')
                    attempts = msg.get('attempts')
                    elapsed = msg.get('elapsed')
                    self._append_log(f"\n>>> SENHA ENCONTRADA: {pw}  (tentativas: {attempts}, tempo: {elapsed:.1f}s)\n")
                    self.status_var.set('Senha encontrada!')
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                elif mtype == 'finished':
                    attempts = msg.get('attempts', 0)
                    elapsed = msg.get('elapsed', 0.0)
                    self._append_log(f"\nConcluído. Senha não encontrada. Tentativas: {attempts}  Tempo: {elapsed:.1f}s\n")
                    self.status_var.set('Concluído - senha não encontrada.')
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                elif mtype == 'stopped':
                    attempts = msg.get('attempts', 0)
                    self._append_log(f"\nAtaque cancelado pelo usuário. Tentativas: {attempts}\n")
                    self.status_var.set('Cancelado.')
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                elif mtype == 'error':
                    self._append_log(f"\nErro: {msg.get('error')}\n")
                    self.status_var.set('Erro durante ataque.')
                    self.start_btn.configure(state='normal')
                    self.stop_btn.configure(state='disabled')
                    try:
                        self.progress.stop()
                    except Exception:
                        pass
                self.msg_queue.task_done()
        except queue.Empty:
            pass
        # schedule next poll
        self.root.after(150, self._poll_queue)

# ------------------ Main ------------------

def main():
    # tema: escolha 'darkly', 'flatly', 'litera', etc.
    root = tb.Window(themename="litera")  # ou 'darkly'
    app = ZipCrackerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
