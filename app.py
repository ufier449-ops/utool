import subprocess
from flask import Flask, render_template, request, jsonify

# Inicializa la aplicación Flask
app = Flask(__name__)

@app.route('/')
def home():
    """Sirve la página principal."""
    return render_template('index.html')

@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Este endpoint recibe la notificación (webhook) de la pasarela de pagos.
    Cuando se recibe una petición POST aquí, ejecuta el script de cambio de contraseña.
    """
    print("Webhook recibido. Procesando pago...")
    
    try:
        # Ejecuta el script de Python que cambia la contraseña.
        # Asegúrate de que 'cambiar_contrasena_unlocktool.py' esté en el mismo directorio.
        # Se usa 'python' para asegurar que se ejecute con el intérprete correcto.
        subprocess.run(['python', 'cambiar_contrasena_unlocktool.py'], check=True)
        
        print("Script ejecutado exitosamente.")
        
        # Responde a la pasarela de pago con un '200 OK' para confirmar la recepción.
        return jsonify({'status': 'success'}), 200

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el script: {e}")
        # Responde con un error si el script falla.
        return jsonify({'status': 'error', 'message': 'Failed to run script'}), 500
    except FileNotFoundError:
        print("Error: El script 'cambiar_contrasena_unlocktool.py' no fue encontrado.")
        return jsonify({'status': 'error', 'message': 'Script not found'}), 500

if __name__ == '__main__':
    # Esto permite ejecutar la app localmente para pruebas con 'python app.py'
    # Render usará Gunicorn, por lo que no llegará a esta parte en producción.
    app.run(debug=True, port=5001)
