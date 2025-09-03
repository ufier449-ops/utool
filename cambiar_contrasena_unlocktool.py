import time
import os
import string
import secrets
from playwright.sync_api import sync_playwright, Playwright
import csv
import json
from tkinter import messagebox, simpledialog
import threading
import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from PIL import Image
import pystray
from win10toast import ToastNotifier
from twocaptcha import TwoCaptcha

# --- CONFIGURATION ---
LOGIN_URL = "https://unlocktool.net/post-in/"
CHROME_BINARY_LOCATION = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
ACCOUNTS_FILE = "accounts.json"
CSV_HISTORY_FILE = "password_history.csv"
CONFIG_FILE = "config.json"

# --- DATA MANAGEMENT ---

def load_config() -> dict:
    """Loads configuration from config.json."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}

def save_config(config: dict):
    """Saves configuration to config.json."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        messagebox.showerror("Error de Guardado", f"No se pudo guardar en {CONFIG_FILE}: {e}")

def load_accounts() -> list:
    """Loads account configurations from accounts.json."""
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        messagebox.showerror("Error de Carga", f"No se pudo cargar {ACCOUNTS_FILE}: {e}")
        return []

def save_accounts(accounts: list):
    """Saves all account configurations to accounts.json."""
    try:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=4)
    except IOError as e:
        messagebox.showerror("Error de Guardado", f"No se pudo guardar en {ACCOUNTS_FILE}: {e}")

# --- CORE LOGIC ---

def log_password_to_csv(username: str, password: str, status: str, source: str, interval: str):
    """Logs password change details to the CSV history file."""
    file_exists = os.path.exists(CSV_HISTORY_FILE)
    try:
        with open(CSV_HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(CSV_HISTORY_FILE) == 0:
                writer.writerow(["Timestamp", "Username", "Password", "Status", "Source", "Interval"])
            writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, password, status, source, interval])
    except IOError as e:
        print(f"Error writing to CSV: {e}")

def generate_new_password(length: int = 12) -> str:
    """Generates a secure random password."""
    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password)):
            break
    return password

def get_last_password_info_for_user(username: str) -> tuple[datetime.datetime, str] | None:
    """Reads the timestamp and source of the last successful password change for a specific user."""
    if not os.path.exists(CSV_HISTORY_FILE):
        return None
    try:
        with open(CSV_HISTORY_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reversed(list(reader)):
                if len(row) > 4 and row[1] == username and row[3] == "✅":
                    timestamp_str = row[0]
                    source = row[4]
                    return datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"), source
            return None
    except (IOError, IndexError, ValueError, StopIteration) as e:
        print(f"Error processing CSV history: {e}")
        return None

def get_last_attempt_info_for_user(username: str) -> tuple[str, str] | None:
    """Reads the status and source of the absolute last attempt for a specific user."""
    if not os.path.exists(CSV_HISTORY_FILE):
        return None
    try:
        with open(CSV_HISTORY_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reversed(list(reader)):
                if len(row) > 4 and row[1] == username:
                    status = row[3]
                    source = row[4]
                    return status, source
            return None
    except (IOError, IndexError, ValueError, StopIteration) as e:
        print(f"Error processing CSV history for last attempt: {e}")
        return None

def run_password_change_flow(username: str, current_password: str, new_password: str, log_callback, api_key: str) -> bool:
    """Executes the Playwright flow to change the password, with auto CAPTCHA solving."""
    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(
                headless=False,
                executable_path=CHROME_BINARY_LOCATION,
                args=["--start-maximized", "--disable-blink-features=AutomationControlled"]
            )
            page = browser.new_page()
            page.set_default_timeout(30000)

            log_callback("Navegando a la página de inicio de sesión...")
            page.goto(LOGIN_URL)

            page.fill("#id_username", username)
            page.fill("#id_password", current_password)
            log_callback("Campos de usuario y contraseña rellenados.")

            if api_key:
                log_callback("API Key detectada. Intentando resolver CAPTCHA...")
                try:
                    recaptcha_element = page.wait_for_selector(".g-recaptcha", timeout=10000)
                    sitekey = recaptcha_element.get_attribute("data-sitekey")
                    log_callback(f"Sitekey de reCAPTCHA encontrada: {sitekey[:30]}...")

                    solver_config = {
                        'apiKey': api_key,
                        'googlekey': sitekey,
                        'pageurl': page.url
                    }
                    solver = TwoCaptcha(**solver_config)
                    log_callback("Enviando CAPTCHA a resolver...")
                    result = solver.recaptcha()
                    
                    log_callback("CAPTCHA resuelto. Enviando solución...")
                    page.evaluate(f"document.getElementById('g-recaptcha-response').innerHTML = '{result['code']}';")
                    page.click("button[type='submit']")
                    log_callback("Formulario de inicio de sesión enviado.")

                except Exception as captcha_error:
                    log_callback(f"Error resolviendo CAPTCHA: {captcha_error}")
                    log_callback("Por favor, resuelva el CAPTCHA manualmente para continuar.")
                    page.wait_for_url(lambda url: url != LOGIN_URL, timeout=300000)
            else:
                log_callback("="*50)
                log_callback("No se encontró API Key. Por favor, resuelva el CAPTCHA manualmente.")
                log_callback("El script continuará cuando detecte el inicio de sesión.")
                log_callback("="*50)
                page.wait_for_url(lambda url: url != LOGIN_URL, timeout=300000)

            log_callback("\n¡Inicio de sesión detectado (URL ha cambiado)!")

            page.goto("https://unlocktool.net/password-change/")
            log_callback("Navegando a la sección de cambio de contraseña...")

            page.fill("#id_old_password", current_password)
            page.fill("#id_new_password1", new_password)
            page.fill("#id_new_password2", new_password)
            page.click("button[type='submit']:has-text('Change password')")
            log_callback("Formulario de cambio de contraseña enviado.")

            page.wait_for_url("**/password-change/done**")
            log_callback("ÉXITO: Contraseña cambiada exitosamente.")
            return True

        except Exception as e:
            log_callback(f"Error durante la automatización: {e}")
            return False
        finally:
            if browser:
                browser.close()

# --- GUI ---

class AccountTab(ttk.Frame):
    def __init__(self, parent, app, account_info: dict, is_new=False):
        super().__init__(parent)
        self.parent = parent
        self.app = app
        self.account_info = account_info
        self.is_new = is_new
        self.running = False
        self.immediate_change_requested = False
        self.cycle_end_time = None
        self.countdown_var = tk.StringVar(value="N/A")
        self.last_password_age_var = tk.StringVar(value="Calculando...")
        self.create_widgets()
        self.load_account_data()
        if not self.is_new:
            self.update_password_age_label()
            self.update_countdown_label()
            self.check_and_auto_change()

    def create_widgets(self):
        # ... (Widget creation remains the same)
        ttk.Label(self, text="Usuario:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.user_entry = ttk.Entry(self, width=40)
        self.user_entry.grid(row=0, column=1, columnspan=3, sticky=tk.EW, pady=2)

        ttk.Label(self, text="Contraseña Actual:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.current_pass_entry = ttk.Entry(self, width=40)
        self.current_pass_entry.grid(row=1, column=1, columnspan=3, sticky=tk.EW, pady=2)

        ttk.Label(self, text="Nueva Contraseña:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.new_pass_entry = ttk.Entry(self, width=40, state="readonly")
        self.new_pass_entry.grid(row=2, column=1, columnspan=3, sticky=tk.EW, pady=2)

        ttk.Label(self, text="Intervalo de Ejecución:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.interval_var = tk.StringVar()
        self.interval_combobox = ttk.Combobox(self, textvariable=self.interval_var, values=["6 horas", "12 horas", "24 horas"], state="readonly")
        self.interval_combobox.grid(row=3, column=1, columnspan=3, sticky=tk.EW, pady=2)
        self.interval_combobox.set("6 horas")

        ttk.Label(self, text="Última contraseña creada hace:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Label(self, textvariable=self.last_password_age_var, foreground="blue").grid(row=4, column=1, columnspan=3, sticky=tk.EW, pady=5)

        self.start_button = ttk.Button(self, text="Iniciar Ciclo", command=self.start_process_thread)
        self.start_button.grid(row=5, column=0, pady=10, sticky=tk.EW)

        self.stop_button = ttk.Button(self, text="Detener Ciclo", command=self.stop_process_thread, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1, pady=10, sticky=tk.EW)

        self.immediate_change_button = ttk.Button(self, text="Cambio Inmediato", command=self.trigger_immediate_change)
        self.immediate_change_button.grid(row=5, column=2, pady=10, sticky=tk.EW)

        self.copy_message_button = ttk.Button(self, text="Copiar Licencia", command=self.copy_license_message, state=tk.DISABLED)
        self.copy_message_button.grid(row=6, column=0, columnspan=3, pady=(5,10), sticky=tk.EW)

        ttk.Label(self, text="Próximo cambio en:").grid(row=7, column=0, sticky=tk.W, pady=5)
        ttk.Label(self, textvariable=self.countdown_var, foreground="green").grid(row=7, column=1, columnspan=3, sticky=tk.EW, pady=5)

        self.log_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=15)
        self.log_area.grid(row=8, column=0, columnspan=4, sticky=tk.NSEW)
        self.log_area.config(state=tk.NORMAL)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(8, weight=1)

    def log_message(self, message):
        self.log_area.insert(tk.END, f"{datetime.datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.log_area.see(tk.END)
        self.app.update_idletasks()

    def load_account_data(self):
        self.user_entry.insert(0, self.account_info.get("username", ""))
        self.current_pass_entry.insert(0, self.account_info.get("password", ""))
        self.interval_var.set(self.account_info.get("interval", "6 horas"))
        if self.is_new:
            self.log_message("Nueva pestaña de cuenta. Rellena los datos y pulsa 'Guardar Todas las Cuentas'.")

    def get_account_data(self) -> dict:
        return {
            "username": self.user_entry.get(),
            "password": self.current_pass_entry.get(),
            "interval": self.interval_var.get()
        }

    def update_password_age_label(self):
        # ... (This method remains the same)
        username = self.user_entry.get()
        if not username:
            self.last_password_age_var.set("Usuario no definido.")
            return

        last_info = get_last_password_info_for_user(username)
        if last_info:
            last_timestamp, _ = last_info
            age = datetime.datetime.now() - last_timestamp
            days, rem = divmod(age.total_seconds(), 86400)
            hours, rem = divmod(rem, 3600)
            minutes, _ = divmod(rem, 60)
            age_str = f"{int(hours)}h {int(minutes)}m"
            if days > 0:
                age_str = f"{int(days)}d, " + age_str
            self.last_password_age_var.set(age_str)
        else:
            self.last_password_age_var.set("Aún no se ha generado ninguna.")
        self.after(60000, self.update_password_age_label)


    def start_process_thread(self):
        if not self.user_entry.get() or not self.current_pass_entry.get():
            messagebox.showwarning("Datos incompletos", "El usuario y la contraseña no pueden estar vacíos.")
            return
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.immediate_change_button.config(state=tk.NORMAL)
        self.running = True
        thread = threading.Thread(target=self.run_process, daemon=True)
        thread.start()

    def stop_process_thread(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.immediate_change_button.config(state=tk.DISABLED)
        self.copy_message_button.config(state=tk.DISABLED)
        self.log_message("Proceso detenido por el usuario.")

    def run_process(self):
        self.after(0, lambda: self.copy_message_button.config(state=tk.DISABLED))
        while self.running:
            username = self.user_entry.get()
            current_password = self.current_pass_entry.get()
            source = "Automático"
            if self.immediate_change_requested:
                source = "Manual"
                self.after(0, lambda: self.immediate_change_button.config(state=tk.DISABLED))
                self.immediate_change_requested = False

            new_password = generate_new_password()
            self.new_pass_entry.config(state=tk.NORMAL)
            self.new_pass_entry.delete(0, tk.END)
            self.new_pass_entry.insert(0, new_password)
            self.new_pass_entry.config(state="readonly")

            self.log_message(f"--- Iniciando cambio de contraseña para {username} ---")
            api_key = self.app.config.get("api_key")
            success = run_password_change_flow(username, current_password, new_password, self.log_message, api_key)

            if success:
                log_password_to_csv(username, new_password, "✅", source, self.interval_var.get())
                self.account_info['password'] = new_password
                self.app.update_account_password(username, new_password)
                self.log_message("Contraseña actualizada en el archivo de cuentas.")
                self.log_message("Proceso completado con éxito.")
                if source == "Manual":
                    self.after(0, lambda: self.copy_message_button.config(state=tk.NORMAL))

                self.current_pass_entry.delete(0, tk.END)
                self.current_pass_entry.insert(0, new_password)
            else:
                log_password_to_csv(username, new_password, "❌", source, self.interval_var.get())
                self.log_message("El proceso de cambio de contraseña falló.")

            if not self.running: break

            hours = int(self.interval_var.get().split(" ")[0])
            self.cycle_end_time = datetime.datetime.now() + datetime.timedelta(hours=hours)
            self.update_countdown_label()
            self.log_message(f"Esperando {hours} horas para el próximo ciclo...")

            notification_sent = False
            for i in range(hours * 3600):
                if not self.running or self.immediate_change_requested: break
                time_remaining = self.cycle_end_time - datetime.datetime.now()
                if not notification_sent and time_remaining.total_seconds() <= 300 and time_remaining.total_seconds() > 0:
                    self.app.toaster.show_toast(
                        "Cambio de Contraseña UnlockTool",
                        f"¡Atención! La contraseña para {username} cambiará en menos de 5 minutos.",
                        duration=10,
                        threaded=True
                    )
                    self.log_message("Notificación de cambio inminente enviada.")
                    notification_sent = True
                time.sleep(1)
            
            if self.immediate_change_requested:
                self.log_message("Detectado cambio inmediato. Reiniciando ciclo.")
                continue
            if not self.running: break
        
        self.log_message("Bucle de ejecución finalizado.")
        self.stop_process_thread()

    def trigger_immediate_change(self):
        self.log_message("Solicitando cambio inmediato...")
        self.immediate_change_requested = True
        if not self.running:
            self.start_process_thread()

    def update_countdown_label(self):
        # ... (This method remains the same)
        if self.cycle_end_time:
            remaining = self.cycle_end_time - datetime.datetime.now()
            if remaining.total_seconds() > 0:
                h, rem = divmod(remaining.total_seconds(), 3600)
                m, s = divmod(rem, 60)
                self.countdown_var.set(f"{int(h):02}:{int(m):02}:{int(s):02}")
            else:
                self.countdown_var.set("¡En curso!")
        else:
            self.countdown_var.set("N/A")
        self.after(1000, self.update_countdown_label)

    def check_and_auto_change(self):
        # ... (This method remains the same)
        username = self.user_entry.get()
        if not username: return

        last_attempt_status, _ = get_last_attempt_info_for_user(username) or (None, None)

        if last_attempt_status == "❌":
            self.log_message("El último intento de cambio falló. Se permite un reintento manual.")
            self.start_button.config(state=tk.NORMAL)
            self.immediate_change_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        last_success_info = get_last_password_info_for_user(username)
        
        if not last_success_info:
            self.log_message("No hay registro de cambios. Iniciando primer cambio automático.")
            self.start_process_thread()
            return

        last_timestamp, last_source = last_success_info
        interval_hours = int(self.interval_var.get().split(" ")[0])
        threshold = datetime.timedelta(hours=interval_hours)
        expected_cycle_end_time = last_timestamp + threshold

        if last_source == "Manual" and datetime.datetime.now() < expected_cycle_end_time:
            self.log_message(f"El último cambio fue MANUAL. Bloqueado hasta {expected_cycle_end_time.strftime('%Y-%m-%d %H:%M:%S')}.")
            self.cycle_end_time = expected_cycle_end_time
            self.start_button.config(state=tk.DISABLED)
            self.immediate_change_button.config(state=tk.DISABLED)
            self.update_countdown_label()
            return
        
        if datetime.datetime.now() - last_timestamp >= threshold:
            self.log_message("Tiempo de ciclo cumplido. Iniciando cambio automático.")
            self.start_process_thread()
        else:
            self.log_message("Aún no se requiere cambio automático. Reanudando ciclo.")
            self.cycle_end_time = expected_cycle_end_time
            self.start_process_thread()

    def copy_license_message(self):
        # ... (This method remains the same)
        interval_hours = self.interval_var.get().split(" ")[0]
        username = self.user_entry.get()
        new_password = self.new_pass_entry.get()
        if not new_password:
            messagebox.showwarning("Sin Contraseña", "No hay nueva contraseña para copiar.")
            return
        message = (f"🎁 ¡Felicidades! 🎁\n\n"
                   f"✅ ¡Tu licencia de UnlockTool por {interval_hours} horas ya está lista! ✅\n\n"
                   f"⭐ Usuario:\n{username}\n"
                   f"⭐ Contraseña:\n{new_password}\n\n"
                   f"¡Aprovechá a full para facturar como un campeón! 😉\n"
                   f"Gracias por confiar 🫂")
        self.clipboard_clear()
        self.clipboard_append(message)
        self.log_message("Mensaje de licencia copiado.")


class HistoryWindow(tk.Toplevel):
    # ... (This class remains the same)
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Historial de Contraseñas")
        self.geometry("800x500")

        cols = ("Timestamp", "Username", "Password", "Status", "Source", "Interval")
        self.history_tree = ttk.Treeview(self, columns=cols, show="headings")
        for col in cols:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        self.history_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(btn_frame, text="Refrescar", command=self.load_history).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Copiar Usuario", command=lambda: self.copy_from_history(1)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copiar Contraseña", command=lambda: self.copy_from_history(2)).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Eliminar Historial", command=self.clear_history).pack(side=tk.LEFT, padx=5)

        self.load_history()

    def load_history(self):
        for i in self.history_tree.get_children():
            self.history_tree.delete(i)
        if not os.path.exists(CSV_HISTORY_FILE): return
        with open(CSV_HISTORY_FILE, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
                for row in reversed(list(reader)):
                    self.history_tree.insert("", tk.END, values=row)
            except (StopIteration, IndexError):
                pass

    def copy_from_history(self, col_index):
        selected_item = self.history_tree.focus()
        if not selected_item: return
        value = self.history_tree.item(selected_item, "values")[col_index]
        self.clipboard_clear()
        self.clipboard_append(value)
        messagebox.showinfo("Copiado", f"'{value}' copiado al portapapeles.")

    def clear_history(self):
        if messagebox.askyesno("Confirmar Eliminación", "¿Estás seguro de que quieres eliminar TODO el historial de contraseñas?\nEsta acción es irreversible."):
            try:
                if os.path.exists(CSV_HISTORY_FILE):
                    os.remove(CSV_HISTORY_FILE)
                    messagebox.showinfo("Historial Eliminado", "El historial de contraseñas ha sido eliminado exitosamente.")
                    self.load_history()
                else:
                    messagebox.showinfo("Historial No Encontrado", "No se encontró ningún historial para eliminar.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar el historial: {e}")


class PasswordChangerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cambiador de Contraseña UnlockTool (Multi-Cuenta)")
        self.geometry("900x750")

        self.config = load_config()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.tab_context_menu = tk.Menu(self, tearoff=0)
        self.tab_context_menu.add_command(command=self.close_tab, label="Cerrar Pestaña")
        self.bind_all("<Control-w>", self.close_tab_event)
        self.right_clicked_tab = None

        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(top_frame, text="Guardar Todas las Cuentas", command=self.save_all_accounts).pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Ver Historial", command=self.open_history_window).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Cerrar Pestaña Actual", command=self.close_tab_event).pack(side=tk.LEFT, padx=5)
        
        self.startup_var = tk.BooleanVar()
        self.startup_checkbutton = ttk.Checkbutton(top_frame, text="Iniciar con Windows", variable=self.startup_var, command=self.toggle_startup)
        self.startup_checkbutton.pack(side=tk.LEFT, padx=10)

        api_key_frame = ttk.LabelFrame(self, text="Configuración Anti-Captcha")
        api_key_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(api_key_frame, text="2Captcha API Key:").pack(side=tk.LEFT, padx=5)
        self.api_key_entry = ttk.Entry(api_key_frame, width=50)
        self.api_key_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.api_key_entry.insert(0, self.config.get("api_key", ""))
        ttk.Button(api_key_frame, text="Guardar Key", command=self.save_api_key).pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.notebook.enable_traversal()
        self.notebook.bind("<Button-3>", self.show_tab_context_menu)

        self.toaster = ToastNotifier()

        self.load_all_accounts()
        self._update_startup_checkbutton_state()

    def save_api_key(self):
        self.config["api_key"] = self.api_key_entry.get()
        save_config(self.config)
        messagebox.showinfo("Guardado", "La API Key ha sido guardada.")

    def show_tab_context_menu(self, event):
        # ... (This method remains the same)
        try:
            self.right_clicked_tab = self.notebook.identify(event.x, event.y)
            tab_text = self.notebook.tab(self.right_clicked_tab, "text")
            if tab_text.strip() == '+':
                return
            self.tab_context_menu.tk_popup(event.x_root, event.y_root)
        except tk.TclError:
            pass

    def close_tab_event(self, event=None):
        self.close_tab()

    def close_tab(self):
        # ... (This method remains the same)
        if self.right_clicked_tab:
            tab_to_close = self.right_clicked_tab
            self.right_clicked_tab = None
        else:
            tab_to_close = self.notebook.select()

        if not tab_to_close:
            return

        if self.notebook.tab(tab_to_close, "text").strip() == '+':
            return

        account_tabs = [tab for tab in self.notebook.tabs() if self.notebook.tab(tab, "text").strip() != '+']
        if len(account_tabs) <= 1:
            messagebox.showinfo("Acción no permitida", "No se puede cerrar la última pestaña de cuenta.")
            return

        if messagebox.askyesno("Confirmar Cierre", "¿Estás seguro de que quieres cerrar esta pestaña?\nLos cambios no guardados en esta pestaña se perderán y el proceso en segundo plano (si está activo) se detendrá."):
            frame = self.notebook.nametowidget(tab_to_close)
            if isinstance(frame, AccountTab) and frame.running:
                frame.stop_process_thread()
            
            self.notebook.forget(tab_to_close)
            frame.destroy()
            self.update_tab_titles()

    def update_tab_titles(self):
        # ... (This method remains the same)
        for i, tab_id in enumerate(self.notebook.tabs()):
            try:
                if self.notebook.tab(tab_id, "text").strip() == '+':
                    continue
            except tk.TclError:
                continue
            
            frame = self.notebook.nametowidget(tab_id)
            if isinstance(frame, AccountTab):
                username = frame.user_entry.get() or "Nueva Cuenta"
                new_title = f"{i + 1} - {username}"
                self.notebook.tab(tab_id, text=new_title)

    def load_all_accounts(self):
        # ... (This method remains the same)
        accounts = load_accounts()
        if not accounts:
            self.add_new_tab(is_first_time=True)
        else:
            for acc in accounts:
                self.add_new_tab(account_info=acc)
        
        self.update_tab_titles()
        self.add_plus_tab()

    def add_plus_tab(self):
        # ... (This method remains the same)
        plus_frame = ttk.Frame(self.notebook)
        self.notebook.add(plus_frame, text=' + ')
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, event):
        # ... (This method remains the same)
        idx = event.widget.index("current")
        try:
            selected_tab_text = event.widget.tab(idx, "text")
        except tk.TclError:
            return
        if selected_tab_text.strip() == '+':
            for i, tab_id in enumerate(self.notebook.tabs()):
                try:
                    current_tab_text = self.notebook.tab(tab_id, "text")
                except tk.TclError:
                    continue
                
                if current_tab_text.strip() == '+':
                    continue
                
                frame = self.notebook.nametowidget(tab_id)
                if isinstance(frame, AccountTab):
                    username = frame.user_entry.get().strip()
                    password = frame.current_pass_entry.get().strip()
                    
                    if not username or not password:
                        messagebox.showwarning(
                            "Datos Incompletos",
                            f"La pestaña '{current_tab_text}' tiene campos de usuario o contraseña vacíos.\n"
                            "Por favor, rellena los datos o cierra la pestaña antes de añadir una nueva."
                        )
                        self.notebook.select(tab_id) 
                        return
            plus_tab_index = -1
            for i, tab_id in enumerate(self.notebook.tabs()):
                if self.notebook.tab(tab_id, "text").strip() == '+':
                    plus_tab_index = i
                    break
            
            if plus_tab_index != -1:
                self.add_new_tab(insert_at=plus_tab_index)
                self.update_tab_titles()
                self.notebook.select(plus_tab_index)

    def add_new_tab(self, account_info=None, is_first_time=False, insert_at=None):
        # ... (This method remains the same)
        if account_info is None:
            account_info = {}
        
        is_new = not bool(account_info)
        tab_name = account_info.get("username", "Nueva Cuenta")
        
        account_frame = AccountTab(self.notebook, self, account_info, is_new=is_new)
        
        if insert_at is not None:
            self.notebook.insert(insert_at, account_frame, text=tab_name)
        else:
            self.notebook.add(account_frame, text=tab_name)
        
        if is_first_time:
            account_frame.log_message("Bienvenido. Añade los datos de tu primera cuenta y pulsa 'Guardar Todas las Cuentas'.")

    def save_all_accounts(self):
        # ... (This method remains the same)
        accounts_data = []
        for i, tab in enumerate(self.notebook.tabs()):
            try:
                tab_text = self.notebook.tab(tab, "text")
            except tk.TclError:
                continue
            
            if tab_text.strip() == '+':
                continue
            
            frame = self.notebook.nametowidget(tab)
            if isinstance(frame, AccountTab):
                data = frame.get_account_data()
                if not data.get("username"):
                    messagebox.showwarning("Datos Incompletos", f"La pestaña #{i+1} no tiene nombre de usuario. No se guardará.")
                    continue
                accounts_data.append(data)
        
        save_accounts(accounts_data)
        self.update_tab_titles()
        messagebox.showinfo("Guardado", "Todas las configuraciones de las cuentas han sido guardadas.")

    def update_account_password(self, username_to_update, new_password):
        # ... (This method remains the same)
        all_accounts = load_accounts()
        account_found = False
        for acc in all_accounts:
            if acc.get("username") == username_to_update:
                acc["password"] = new_password
                account_found = True
                break
        if account_found:
            save_accounts(all_accounts)
        else:
            print(f"Warning: Could not find account {username_to_update} to update password in {ACCOUNTS_FILE}")

    def open_history_window(self):
        self.history_window = HistoryWindow(self)

    def on_closing(self):
        self.hide_to_tray()

    def setup_tray_icon(self):
        # ... (This method remains the same)
        image = Image.new('RGB', (64, 64), (0, 0, 0))
        menu = (
            pystray.MenuItem('Mostrar', self.show_window),
            pystray.MenuItem('Salir', self.quit_app)
        )
        self.icon = pystray.Icon("UnlockTool Changer", image, "UnlockTool Changer", menu)
        self.icon.run_detached()

    def hide_to_tray(self):
        self.withdraw()
        if not hasattr(self, 'icon') or not self.icon.running:
            self.setup_tray_icon()

    def show_window(self):
        self.deiconify()
        if hasattr(self, 'icon') and self.icon.running:
            self.icon.stop()

    def quit_app(self):
        # ... (This method remains the same)
        for tab_id in self.notebook.tabs():
            try:
                frame = self.notebook.nametowidget(tab_id)
                if isinstance(frame, AccountTab) and frame.running:
                    frame.stop_process_thread()
            except Exception as e:
                print(f"Error stopping tab process: {e}")

        if hasattr(self, 'icon'):
            self.icon.stop()
        self.after(0, self.destroy)

    def _get_startup_shortcut_path(self):
        # ... (This method remains the same)
        startup_folder = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        return os.path.join(startup_folder, "unlocktool_changer_startup.bat")

    def toggle_startup(self):
        if self.startup_var.get():
            self._enable_startup()
        else:
            self._disable_startup()

    def _enable_startup(self):
        # ... (This method remains the same)
        shortcut_path = self._get_startup_shortcut_path()
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        batch_content = f'''@echo off
cd /d "{script_dir}"
pythonw "{script_path}"
'''
        try:
            with open(shortcut_path, "w") as f:
                f.write(batch_content)
            messagebox.showinfo("Inicio con Windows", "El programa se ha configurado para iniciar con Windows.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el acceso directo de inicio: {e}")
            self.startup_var.set(False)

    def _disable_startup(self):
        # ... (This method remains the same)
        shortcut_path = self._get_startup_shortcut_path()
        try:
            if os.path.exists(shortcut_path):
                os.remove(shortcut_path)
            messagebox.showinfo("Inicio con Windows", "El programa ya no se iniciará con Windows.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo eliminar el acceso directo de inicio: {e}")
            self.startup_var.set(True)

    def _update_startup_checkbutton_state(self):
        # ... (This method remains the same)
        shortcut_path = self._get_startup_shortcut_path()
        if os.path.exists(shortcut_path):
            self.startup_var.set(True)
        else:
            self.startup_var.set(False)

if __name__ == "__main__":
    app = PasswordChangerApp()
    app.mainloop()