import datetime
import hashlib
import os
import secrets
from functools import wraps

import jwt
from authlib.integrations.flask_client import OAuth
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for, send_from_directory
from flask_login import LoginManager, UserMixin
from sqlalchemy import create_engine, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_muy_segura'  # Cambiar por una clave segura
oauth = OAuth(app)

PRIVATE_FOLDER = "private_keys"
os.makedirs(PRIVATE_FOLDER, exist_ok=True)
UPLOAD_FOLDER = "archivos"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
FIRMAS_FOLDER = "firmas"
os.makedirs(FIRMAS_FOLDER, exist_ok=True)

# Clave secreta para JWT (en producción usar variable de entorno)
JWT_SECRET_KEY = secrets.token_urlsafe(32)  # 256 bits de entropía
JWT_ALGORITHM = 'HS256'

# Conexión a MySQL
engine = create_engine("mysql+pymysql://diplomado:diplomado@persistencia:3306/persistencia")

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'access_type': 'offline'},
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    request_token_params={'scope': 'email profile'},
    request_token_url=None,
)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

users = {}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

#-------------------------------------JWT---------------------------------------
def generate_jwt_token(user_id, username):
    """Genera un token JWT para el usuario"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expira en 1 hora
        'iat': datetime.datetime.utcnow(),  # Fecha de emisión
        'iss': 'diplomado-jwt-app'  # Emisor
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={
            "verify_exp": True,
            "verify_signature": True,
            "require": ["exp", "iat", "iss"],
        })
        if payload["iss"] != "diplomado-jwt-app":
            raise ValueError("Issuer inválido")
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def jwt_required(f):
    """Decorador para rutas que requieren autenticación JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token and 'jwt_token' in session:
            token = session['jwt_token']
        if not token:
            if request.is_json:
                return jsonify({'error': 'Token requerido'}), 401
            else:
                return redirect(url_for('login'))
        payload = verify_jwt_token(token)
        if not payload:
            session.clear()
            if request.is_json:
                return jsonify({'error': 'Token inválido o expirado'}), 401
            else:
                return redirect(url_for('login'))
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


#------------------------------------- Autenticación y Registro ---------------------------------------
# Rutas de autenticación

@app.route("/login/google")
def login_google():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/authorize/google")
def authorize_google():
    token = oauth.google.authorize_access_token()
    nonce = session.get('nonce')
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    email = user_info.get("email")
    nombre = user_info.get("name") or email.split("@")[0]

    with engine.connect() as conn:
        result = conn.execute(text("SELECT id, username FROM usuarios WHERE email = :email"), {"email": email}).fetchone()

        if not result:
            username = nombre.replace(" ", "_").lower()
            conn.execute(text("INSERT INTO usuarios (username, email, password_hash, activo) VALUES (:u, :e, '', TRUE)"), {
                "u": username,
                "e": email
            })
            conn.commit()
            result = conn.execute(text("SELECT id, username FROM usuarios WHERE email = :email"), {"email": email}).fetchone()

        user_id, username = result
        token_jwt = generate_jwt_token(user_id, username)

        session['jwt_token'] = token_jwt
        session['user_id'] = user_id
        session['username'] = username

    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            if request.is_json:
                return jsonify({'error': 'Todos los campos son requeridos'}), 400
            else:
                return render_template('register.html', error='Todos los campos son requeridos')
        
        # Verificar si el usuario ya existe
        with engine.connect() as conn:
            existing_user = conn.execute(
                text("SELECT id FROM usuarios WHERE username = :username OR email = :email"),
                {"username": username, "email": email}
            ).fetchone()
            
            if existing_user:
                if request.is_json:
                    return jsonify({'error': 'Usuario o email ya existe'}), 400
                else:
                    return render_template('register.html', error='Usuario o email ya existe')
            
            # Crear nuevo usuario
            password_hash = generate_password_hash(password)
            conn.execute(
                text("INSERT INTO usuarios (username, email, password_hash) VALUES (:username, :email, :password_hash)"),
                {"username": username, "email": email, "password_hash": password_hash}
            )
            conn.commit()

        # Si es una petición JSON (API), devolver JSON
        if request.is_json:
            return jsonify({'message': 'Usuario registrado exitosamente'}), 201
        else:
            # Si es formulario HTML, mostrar mensaje y redirigir al login
            return render_template('register.html', 
                                 success='Usuario registrado exitosamente. Redirigiendo al login...', 
                                 redirect_to_login=True)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'error': 'Username y password son requeridos'}), 400
            else:
                return render_template('login.html', error='Username y password son requeridos')
        
        # Verificar credenciales
        with engine.connect() as conn:
            user = conn.execute(
                text("SELECT id, username, password_hash FROM usuarios WHERE username = :username AND activo = TRUE"),
                {"username": username}
            ).fetchone()
            
            if user and check_password_hash(user[2], password):
                # Generar JWT token
                token = generate_jwt_token(user[0], user[1])

                # Si es una petición JSON (API), devolver JSON
                if request.is_json:
                    return jsonify({
                        'message': 'Login exitoso',
                        'token': token,
                        'user_id': user[0],
                        'username': user[1]
                    }), 200
                else:
                    # Si es formulario HTML, guardar token en sesión y redirigir
                    session['jwt_token'] = token
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    return redirect(url_for('index'))
            else:
                if request.is_json:
                    return jsonify({'error': 'Credenciales inválidas'}), 401
                else:
                    return render_template('login.html', error='Credenciales inválidas')
    
    return render_template('login.html')

# Ruta protegida requiere JWT
@app.route("/", methods=["GET", "POST"])
@jwt_required
def index():
    user_id = request.current_user.get('user_id')
    username = request.current_user.get('username', 'Usuario')

    if request.method == "POST":
        nombre = request.form["nombre_clave"]

        with engine.connect() as conn:
            # Verificar si el usuario ya tiene una llave
            existing = conn.execute(
                text("SELECT id FROM llaves_publicas WHERE user_id = :uid"),
                {"uid": user_id}
            ).fetchone()

            if existing:
                return render_template("index.html", username=username, error="Ya has generado una llave.")

            # Generar llaves
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            # Serializar
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Guardar pública en base de datos
            conn.execute(text("""
                            INSERT INTO llaves_publicas (user_id, nombre_clave, llave)
                            VALUES (:uid, :nombre, :llave)
                        """), {"uid": user_id, "nombre": nombre, "llave": pub_pem.decode("utf-8")})
            conn.commit()

        # Guardar privada
        priv_path = os.path.join(PRIVATE_FOLDER, f"{nombre}_private.pem")
        with open(priv_path, "wb") as f:
            f.write(priv_pem)

        return send_file(priv_path, as_attachment=True)

    with engine.connect() as conn:
        # Obtener archivos propios
        archivos_propios = conn.execute(text("""
            SELECT DISTINCT a.id, a.nombre, a.hash, a.fecha_subida, 
                   'Propio' as tipo,
                   u.username as propietario
            FROM archivos a
            JOIN usuarios u ON a.usuario_id = u.id
            WHERE a.usuario_id = :usuario_id
        """), {"usuario_id": user_id}).fetchall()
        
        # Obtener archivos compartidos conmigo
        archivos_compartidos = conn.execute(text("""
            SELECT DISTINCT a.id, a.nombre, a.hash, a.fecha_subida, 
                   'Compartido' as tipo,
                   u.username as propietario
            FROM archivos a
            JOIN archivos_compartidos ac ON a.id = ac.archivo_id
            JOIN usuarios u ON a.usuario_id = u.id
            WHERE ac.compartido_con_id = :usuario_id
        """), {"usuario_id": user_id}).fetchall()
        
        # Combinar todos los archivos
        todos_archivos = list(archivos_propios) + list(archivos_compartidos)
        
        # Para cada archivo, obtener quién lo ha firmado
        archivos_con_firmas = []
        for archivo in todos_archivos:
            archivo_dict = {
                'id': archivo.id,
                'nombre': archivo.nombre,
                'hash': archivo.hash,
                'fecha_subida': archivo.fecha_subida,
                'tipo': archivo.tipo,
                'propietario': archivo.propietario
            }
            
            # Obtener firmas del archivo
            firmas = conn.execute(text("""
                SELECT u.username, f.fecha_firma, f.valida
                FROM firmas f
                JOIN usuarios u ON f.usuario_id = u.id
                WHERE f.archivo_id = :archivo_id
                ORDER BY f.fecha_firma DESC
            """), {"archivo_id": archivo.id}).fetchall()
            
            archivo_dict['firmas'] = [
                {
                    'usuario': firma.username,
                    'fecha': firma.fecha_firma,
                    'valida': firma.valida
                }
                for firma in firmas
            ]
            
            archivos_con_firmas.append(archivo_dict)

    return render_template("index.html", username=username, archivos=archivos_con_firmas)

# Ruta para logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Ruta para verificar token
@app.route('/verify-token', methods=['POST'])
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({'valid': False, 'error': 'Token no proporcionado'}), 400

    token = auth_header.split(" ")[1]

    payload = verify_jwt_token(token)
    if payload:
        return jsonify({'valid': True, 'payload': payload}), 200
    else:
        return jsonify({'valid': False, 'error': 'Token inválido o expirado'}), 401



# --------------------------------- Rutas de archivos y firmas ---------------------------------
@app.route("/upload", methods=["POST"])
@jwt_required
def upload_file():
    if 'archivo' not in request.files:
        return jsonify({"error": "No se envió archivo"}), 400

    file = request.files['archivo']
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # hash
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        sha256.update(f.read())
    hash_hex = sha256.hexdigest()

    # Guardar en la base de datos
    with engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO archivos (nombre, ruta, hash, usuario_id)
            VALUES (:nombre, :ruta, :hash, :usuario_id)
        """), {
            "nombre": filename,
            "ruta": filepath,
            "hash": hash_hex,
            "usuario_id": request.current_user['user_id']
        })
        conn.commit()

    return jsonify({"message": "Archivo subido", "hash": hash_hex})


@app.route("/firmar", methods=["POST"])
@jwt_required
def firmar_archivo():
    archivo_id = request.form.get("archivo_id")
    llave = request.files.get("llave")

    if not archivo_id or not llave:
        return jsonify({"error": "Datos incompletos"}), 400

    user_id = request.current_user['user_id']

    with engine.connect() as conn:
        # Verificar que el archivo existe y el usuario tiene acceso (propio o compartido)
        result = conn.execute(text("""
            SELECT a.ruta, a.nombre 
            FROM archivos a
            WHERE a.id = :id 
            AND (
                a.usuario_id = :user_id 
                OR EXISTS (
                    SELECT 1 FROM archivos_compartidos ac 
                    WHERE ac.archivo_id = a.id 
                    AND ac.compartido_con_id = :user_id
                )
            )
        """), {"id": archivo_id, "user_id": user_id}).fetchone()
        
        if not result:
            return jsonify({"error": "Archivo no encontrado o sin permisos"}), 404

        ruta_archivo, nombre_archivo = result

        # Verificar si ya firmó este archivo
        firma_existente = conn.execute(text("""
            SELECT id FROM firmas 
            WHERE archivo_id = :archivo_id AND usuario_id = :user_id
        """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()
        
        if firma_existente:
            return jsonify({"error": "Ya has firmado este archivo"}), 400

    with open(ruta_archivo, "rb") as f:
        contenido = f.read()

    try:
        private_key = serialization.load_pem_private_key(
            llave.read(),
            password=None
        )
    except Exception as e:
        return jsonify({"error": "Llave privada inválida"}), 400

    # Firmar el contenido
    firma = private_key.sign(
        contenido,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Guardar firma
    ruta_firma = os.path.join(FIRMAS_FOLDER, f"{user_id}_{archivo_id}_{nombre_archivo}.firma")
    with open(ruta_firma, "wb") as f:
        f.write(firma)

    # Validar la firma inmediatamente
    es_valida = True
    try:
        with engine.connect() as conn:
            # Obtener la llave pública del usuario
            llave_publica_row = conn.execute(text("""
                SELECT llave FROM llaves_publicas WHERE user_id = :uid
            """), {"uid": user_id}).fetchone()
            
            if llave_publica_row:
                public_key = serialization.load_pem_public_key(
                    llave_publica_row[0].encode("utf-8")
                )
                public_key.verify(
                    signature=firma,
                    data=contenido,
                    padding=padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hashes.SHA256()
                )
    except:
        es_valida = False

    with engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO firmas (archivo_id, firma, usuario_id, valida)
            VALUES (:archivo_id, :firma, :usuario_id, :valida)
        """), {
            "archivo_id": archivo_id,
            "firma": firma,
            "usuario_id": user_id,
            "valida": es_valida
        })
        conn.commit()

    return jsonify({
        "message": "Archivo firmado",
        "ruta_firma": f"firmas/{os.path.basename(ruta_firma)}",
        "valida": es_valida
    })

@app.route('/firmas/<filename>')
def descargar_firma(filename):
    return send_from_directory('firmas', filename)

@app.route("/verificar", methods=["POST"])
@jwt_required
def verificar_firma():
    archivo_id = request.form.get("archivo_id")
    archivo_firma = request.files.get("firma")  # archivo .firma subido por el usuario

    if not archivo_id or not archivo_firma:
        return jsonify({"error": "Faltan datos"}), 400

    # Leer la firma del archivo subido
    firma_bytes = archivo_firma.read()

    with engine.connect() as conn:
        # Obtener información del archivo
        archivo_info = conn.execute(text("""
                                         SELECT nombre, ruta
                                         FROM archivos
                                         WHERE id = :aid
                                         """), {"aid": archivo_id}).fetchone()

        if not archivo_info:
            return jsonify({"error": "Archivo no encontrado"}), 404

        archivo_nombre, ruta_archivo = archivo_info

        # Leer el contenido del archivo original
        try:
            with open(ruta_archivo, "rb") as f:
                contenido = f.read()
        except FileNotFoundError:
            return jsonify({"error": "Archivo original no encontrado en disco"}), 404

        # Obtener TODAS las llaves públicas de usuarios que han firmado este archivo
        firmantes = conn.execute(text("""
                                      SELECT DISTINCT u.username, lp.llave
                                      FROM firmas f
                                               JOIN usuarios u ON f.usuario_id = u.id
                                               JOIN llaves_publicas lp ON lp.user_id = u.id
                                      WHERE f.archivo_id = :aid
                                      """), {"aid": archivo_id}).fetchall()

        if not firmantes:
            return jsonify({"error": "No hay firmas registradas para este archivo"}), 404

    # Intentar verificar con cada llave pública
    for firmante in firmantes:
        username, llave_publica_pem = firmante

        try:
            public_key = serialization.load_pem_public_key(llave_publica_pem.encode("utf-8"))

            # Intentar verificar la firma con esta llave pública
            public_key.verify(
                signature=firma_bytes,
                data=contenido,
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )

            # Si llegamos aquí, la firma es válida
            return jsonify({
                "valido": True,
                "mensaje": "válida",
                "firmante": username,
                "detalles": f"Firma verificada correctamente. Firmado por: {username}"
            })

        except Exception:
            # Esta llave no corresponde a la firma, continuar con la siguiente
            continue

    # Si ninguna llave pública pudo verificar la firma
    return jsonify({
        "valido": False,
        "mensaje": "inválida",
        "detalles": "La firma no corresponde a ningún usuario que haya firmado este archivo"
    })

# --------------------------------- Nuevas rutas para compartir ---------------------------------
@app.route("/usuarios", methods=["GET"])
@jwt_required
def listar_usuarios():
    """Lista todos los usuarios excepto el actual"""
    user_id = request.current_user['user_id']
    
    with engine.connect() as conn:
        usuarios = conn.execute(text("""
            SELECT id, username, email
            FROM usuarios
            WHERE id != :user_id AND activo = TRUE
            ORDER BY username
        """), {"user_id": user_id}).fetchall()
    
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email
    } for u in usuarios])


@app.route("/compartir", methods=["POST"])
@jwt_required
def compartir_archivo():
    """Compartir un archivo con otro usuario"""
    data = request.get_json() if request.is_json else request.form
    archivo_id = data.get('archivo_id')
    compartir_con_id = data.get('compartir_con_id')
    
    if not archivo_id or not compartir_con_id:
        return jsonify({"error": "Datos incompletos"}), 400
    
    user_id = request.current_user['user_id']
    
    with engine.connect() as conn:
        # Verificar que el archivo pertenece al usuario
        archivo = conn.execute(text("""
            SELECT id FROM archivos 
            WHERE id = :archivo_id AND usuario_id = :user_id
        """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()
        
        if not archivo:
            return jsonify({"error": "Archivo no encontrado o no tienes permisos"}), 404
        
        # Verificar que no esté ya compartido
        compartido = conn.execute(text("""
            SELECT id FROM archivos_compartidos
            WHERE archivo_id = :archivo_id 
            AND compartido_con_id = :compartir_con_id
        """), {
            "archivo_id": archivo_id,
            "compartir_con_id": compartir_con_id
        }).fetchone()
        
        if compartido:
            return jsonify({"error": "El archivo ya está compartido con este usuario"}), 400
        
        # Compartir el archivo
        conn.execute(text("""
            INSERT INTO archivos_compartidos 
            (archivo_id, propietario_id, compartido_con_id)
            VALUES (:archivo_id, :propietario_id, :compartido_con_id)
        """), {
            "archivo_id": archivo_id,
            "propietario_id": user_id,
            "compartido_con_id": compartir_con_id
        })
        conn.commit()
        
        # Obtener información del usuario con quien se compartió
        usuario = conn.execute(text("""
            SELECT username FROM usuarios WHERE id = :id
        """), {"id": compartir_con_id}).fetchone()
    
    return jsonify({
        "message": f"Archivo compartido con {usuario.username}",
        "success": True
    })


@app.route("/archivos/<int:archivo_id>/compartidos", methods=["GET"])
@jwt_required
def obtener_compartidos(archivo_id):
    """Obtener lista de usuarios con quienes se ha compartido un archivo"""
    user_id = request.current_user['user_id']
    
    with engine.connect() as conn:
        # Verificar que el archivo pertenece al usuario
        archivo = conn.execute(text("""
            SELECT id FROM archivos 
            WHERE id = :archivo_id AND usuario_id = :user_id
        """), {"archivo_id": archivo_id, "user_id": user_id}).fetchone()
        
        if not archivo:
            return jsonify({"error": "Archivo no encontrado o no tienes permisos"}), 404
        
        # Obtener usuarios con quienes se compartió
        compartidos = conn.execute(text("""
            SELECT u.id, u.username, u.email, ac.fecha_compartido
            FROM archivos_compartidos ac
            JOIN usuarios u ON ac.compartido_con_id = u.id
            WHERE ac.archivo_id = :archivo_id
            ORDER BY ac.fecha_compartido DESC
        """), {"archivo_id": archivo_id}).fetchall()
    
    return jsonify([{
        'id': c.id,
        'username': c.username,
        'email': c.email,
        'fecha_compartido': c.fecha_compartido.isoformat() if c.fecha_compartido else None
    } for c in compartidos])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))