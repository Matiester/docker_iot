from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import os
import logging
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
import aiomqtt,ssl # <--- AGREGADO
import asyncio # <--- AGREGADO
import json # <--- AGREGADO para el payload MQTT

logging.basicConfig(format='%(asctime)s - CRUD - %(levelname)s - %(message)s', level=logging.INFO)

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

# Configuración de la aplicación (variables de entorno)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret_key_for_dev") # Agregado default por si no está
app.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
app.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
app.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
app.config['PERMANENT_SESSION_LIFETIME'] = 180
mysql = MySQL(app)

# Variables de entorno MQTT (cargadas una vez)
MQTT_SERVER = os.environ.get("SERVIDOR")
MQTT_USERNAME = os.environ.get("MQTT_USR")
MQTT_PASSWORD = os.environ.get("MQTT_PASS")
MQTT_PORT = int(os.environ.get("PUERTO_MQTTS", 8883)) # Puerto MQTTS por defecto 8883

# rutas

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    """Registrar usuario"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("usuario"):
            return "el campo usuario es oblicatorio"

        # Ensure password was submitted
        elif not request.form.get("password"):
            return "el campo contraseña es oblicatorio"

        passhash=generate_password_hash(request.form.get("password"), method='scrypt', salt_length=16)
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO usuarios (usuario, hash) VALUES (%s,%s)", (request.form.get("usuario"), passhash[17:]))
        if mysql.connection.affected_rows():
            flash('Se agregó un usuario')  # usa sesión
            logging.info("se agregó un usuario")
        mysql.connection.commit()
        return redirect(url_for('index'))

    return render_template('registrar.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("usuario"):
            return "el campo usuario es oblicatorio"
        # Ensure password was submitted
        elif not request.form.get("password"):
            return "el campo contraseña es oblicatorio"

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM usuarios WHERE usuario LIKE %s", (request.form.get("usuario"),))
        rows=cur.fetchone()
        if(rows):
            if (check_password_hash('scrypt:32768:8:1$' + rows[2],request.form.get("password"))):
                session.permanent = True
                session["user_id"]=request.form.get("usuario")
                logging.info("se autenticó correctamente")
                return redirect(url_for('index'))
            else:
                flash('usuario o contraseña incorrecto')
                return redirect(url_for('login'))
    return render_template('login.html')

@app.route("/logout")
@require_login
def logout():
    user = session.get("user_id", "desconocido")
    session.clear()
    logging.info(f"El usuario {user} cerró su sesión")
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login')) # Redirigir a login tras logout


# --- NUEVA RUTA PARA COMANDOS MQTT ---
@app.route('/send_mqtt_command', methods=['POST'])
@require_login
def send_mqtt_command():
    if not all([MQTT_SERVER, MQTT_USERNAME, MQTT_PASSWORD, MQTT_PORT]):
        flash("La configuración MQTT no está completa en el servidor.", "danger")
        logging.error("Faltan variables de entorno para la conexión MQTT.")
        return redirect(url_for('index'))

    selected_node = request.form.get('nodo_seleccionado')
    command_type = request.form.get('comando_mqtt')
    setpoint_value = request.form.get('setpoint_valor', '')
    data = 1

    if not selected_node or not command_type:
        flash("Debe seleccionar un nodo y un tipo de comando.", "warning")
        return redirect(url_for('index'))

    if command_type == "setpoint":
        if not setpoint_value:
            flash("Debe indicar un valor para Setpoint.", "warning")
            return redirect(url_for('index'))
        try:
            data = int(setpoint_value)
        except ValueError:
            flash("El valor de Setpoint debe ser un número entero.", "warning")
            return redirect(url_for('index'))


    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.verify_mode = ssl.CERT_REQUIRED
    tls_context.check_hostname = True
    tls_context.load_default_certs()
    async def mqtt_publish():
        async with aiomqtt.Client(
            hostname=MQTT_SERVER,
            port=MQTT_PORT,
            username=MQTT_USERNAME,
            password=MQTT_PASSWORD,
            tls_context=tls_context,
        ) as client:
            logging.info(f"Conectando a MQTT Broker: {MQTT_SERVER}:{MQTT_PORT}")
            await client.publish(selected_node+"/"+command_type, data, qos=1)
            logging.info(f"Comando MQTT enviado: {command_type} a {selected_node}/{command_type} con valor {data}")


    try:
        asyncio.run(mqtt_publish())
        flash(f"Comando '{command_type}' enviado a nodo '{selected_node}' vía MQTT.", "success")
    except aiomqtt.MqttError as e:
        flash(f"Error al enviar comando MQTT: {e}", "danger")
        logging.error(f"Error MQTT: {e}")
    except Exception as e:
        flash(f"Error inesperado: {e}", "danger")
        logging.error(f"Error inesperado: {e}")

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)