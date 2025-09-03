import subprocess
from flask import Flask, render_template, request, jsonify
import os
import threading
# Importa la función principal del worker
from worker import trigger_immediate_change

def log_startup_history():
    history_file = 'historial_sesion.txt'
    if os.path.exists(history_file) and os.path.getsize(history_file) > 0:
        print("--- Contenido del historial de la sesión anterior ---")
        with open(history_file, 'r', encoding='utf-8') as f:
            print(f.read())
        print("----------------------------------------------------")
        # Limpia el historial para la nueva sesión para evitar que crezca indefinidamente
        try:
            os.remove(history_file)
            open(history_file, 'w').close()
            print("El historial de la sesión anterior ha sido mostrado y limpiado.")
        except OSError as e:
            print(f"Error limpiando el archivo de historial: {e}")

# Registra el historial al iniciar la app (si existe)
log_startup_history()

# Inicializa la aplicación Flask
app = Flask(__name__)

@app.route('/')
def home():
    """Sirve una página de bienvenida simple."""
    # El index.html original no es necesario para la funcionalidad del webhook
    return "<h1>Servidor de Webhook para UnlockTool</h1><p>El endpoint está activo en /webhook.</p>"

@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Recibe el webhook y dispara el cambio de contraseña en un hilo separado.
    """
    print("Webhook recibido. Disparando el proceso de cambio de contraseña en segundo plano...")
    
    # Ejecuta la función del worker en un hilo para no bloquear la respuesta HTTP
    thread = threading.Thread(target=trigger_immediate_change)
    thread.start()
    
    # Responde inmediatamente a la pasarela de pago
    return jsonify({'status': 'success', 'message': 'Password change process initiated.'}), 200

if __name__ == '__main__':
    # Esto permite ejecutar la app localmente para pruebas con 'python app.py'
    # Render usará Gunicorn, por lo que no llegará a esta parte en producción.
    app.run(debug=True, port=5001)
