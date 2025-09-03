# Usar la imagen oficial de Playwright con Python
FROM mcr.microsoft.com/playwright/python:v1.55.0-jammy

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo de requerimientos
COPY requirements.txt .

# Instalar las dependencias de Python
# No necesitamos 'playwright install' porque los navegadores ya vienen en la imagen
RUN pip install -r requirements.txt

# Copiar el resto del código de la aplicación
COPY . .

# Exponer el puerto en el que corre la aplicación (Render usa 10000 por defecto)
EXPOSE 10000

# Comando para iniciar la aplicación.
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]
