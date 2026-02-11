import os
import mercadopago
import psycopg2
from psycopg2 import pool
import bcrypt
import jwt
import datetime
import re
import json
import logging
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, session, abort, send_from_directory
from flask_cors import CORS
from functools import wraps
from werkzeug.utils import secure_filename
from supabase import create_client, Client
import base64
from io import BytesIO

# Configuração de logging para Render
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuração para Render
base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'static')
imagens_dir = os.path.join(static_dir, 'imagens_boloes')

os.makedirs(static_dir, exist_ok=True)
os.makedirs(imagens_dir, exist_ok=True)

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Configurações
app.secret_key = os.environ.get('SECRET_KEY', 'lotomaster_sistema_boloes_2024_seguro')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # Aumentado para 500MB (HLS + original temporário)
CORS(app, supports_credentials=True)

# ============================================
# CONEXÃO COM SUPABASE STORAGE - CREDENCIAIS ATUALIZADAS
# ============================================
SUPABASE_URL = "https://dkgzrqbzotwrskdmjxbw.supabase.co"
SUPABASE_KEY = "sb_publishable_MOm9W2-leOa6xKEs0T_ujA_thG_JJSg"
SUPABASE_SERVICE_KEY = "sb_secret_XDQSoUw2htLlYe0dsJEN5w_C5F0BJ22"

supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
supabase_public: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

BUCKET_NAME = "midia-concursos"

def inicializar_supabase_storage():
    """Idêntico ao seu código original"""
    try:
        buckets = supabase_admin.storage.list_buckets()
        bucket_exists = any(bucket.name == BUCKET_NAME for bucket in buckets)
        if not bucket_exists:
            supabase_admin.storage.create_bucket(
                BUCKET_NAME,
                options={
                    "public": True,
                    "file_size_limit": 524288000,  # 500MB
                    "allowed_mime_types": [
                        'image/*',
                        'video/*',
                        'application/pdf',
                        'application/x-mpegURL',   # HLS playlist
                        'video/MP2T'              # HLS segment
                    ]
                }
            )
            logger.info(f"✅ Bucket '{BUCKET_NAME}' criado no Supabase Storage")
        else:
            logger.info(f"✅ Bucket '{BUCKET_NAME}' já existe no Supabase Storage")
        # Criar imagem padrão se não existir
        try:
            files = supabase_admin.storage.from_(BUCKET_NAME).list("imagens")
            default_exists = any(file['name'] == 'default.jpg' for file in files)
            if not default_exists:
                default_image = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
                supabase_admin.storage.from_(BUCKET_NAME).upload(
                    "imagens/default.jpg",
                    default_image,
                    {"content-type": "image/jpeg"}
                )
                logger.info("✅ Imagem padrão criada no Supabase Storage")
        except Exception as e:
            logger.warning(f"⚠️ Não foi possível verificar/criar imagem padrão: {str(e)}")
        return True
    except Exception as e:
        logger.error(f"❌ Erro ao inicializar Supabase Storage: {str(e)}")
        return False

# ============================================
# CONVERSÃO HLS (FFmpeg) - NOVO
# ============================================
def verificar_ffmpeg():
    """Verifica se o FFmpeg está instalado no sistema."""
    return shutil.which("ffmpeg") is not None

def converter_para_hls(caminho_video, nome_base):
    """
    Converte um vídeo para HLS usando FFmpeg.
    Retorna o caminho da pasta temporária com os arquivos gerados (.m3u8 + .ts)
    ou None em caso de erro.
    """
    if not verificar_ffmpeg():
        logger.error("FFmpeg não encontrado no servidor. Instale via aptfile.")
        return None

    pasta_hls = tempfile.mkdtemp()
    playlist = os.path.join(pasta_hls, f"{nome_base}.m3u8")
    segment_pattern = os.path.join(pasta_hls, f"{nome_base}_%03d.ts")

    comando = [
        "ffmpeg", "-i", caminho_video,
        "-profile:v", "baseline",
        "-level", "3.0",
        "-start_number", "0",
        "-hls_time", "10",
        "-hls_list_size", "0",
        "-f", "hls",
        "-hls_segment_filename", segment_pattern,
        playlist
    ]

    try:
        subprocess.run(comando, check=True, capture_output=True, text=True, timeout=600)
        logger.info(f"HLS gerado com sucesso: {playlist}")
        return pasta_hls
    except subprocess.TimeoutExpired:
        logger.error("Tempo limite excedido na conversão HLS")
        shutil.rmtree(pasta_hls, ignore_errors=True)
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro FFmpeg: {e.stderr}")
        shutil.rmtree(pasta_hls, ignore_errors=True)
        return None

def upload_pasta_hls(pasta_hls, prefixo_destino):
    """
    Envia todos os arquivos da pasta HLS para o Supabase.
    Retorna a URL pública da playlist .m3u8.
    """
    try:
        arquivos = os.listdir(pasta_hls)
        if not arquivos:
            return None

        playlist_url = None
        for arquivo in arquivos:
            caminho_local = os.path.join(pasta_hls, arquivo)
            with open(caminho_local, 'rb') as f:
                conteudo = f.read()

            caminho_remoto = f"{prefixo_destino}/{arquivo}"
            mime = "video/MP2T" if arquivo.endswith('.ts') else "application/x-mpegURL"

            supabase_admin.storage.from_(BUCKET_NAME).upload(
                caminho_remoto,
                conteudo,
                {"content-type": mime}
            )

            if arquivo.endswith('.m3u8'):
                playlist_url = f"https://{SUPABASE_URL.split('//')[1]}/storage/v1/object/public/{BUCKET_NAME}/{caminho_remoto}"

        logger.info(f"✅ HLS enviado para Supabase: {playlist_url}")
        return playlist_url
    except Exception as e:
        logger.error(f"❌ Erro no upload HLS: {str(e)}")
        return None
    finally:
        shutil.rmtree(pasta_hls, ignore_errors=True)

# ============================================
# FUNÇÕES DE UPLOAD PARA SUPABASE (MODIFICADAS)
# ============================================
def upload_para_supabase(file, filename, folder="imagens"):
    """
    Função original preservada. Não utilizada para vídeos.
    Mantida para compatibilidade.
    """
    try:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        file_extension = os.path.splitext(filename)[1].lower()
        unique_filename = f"{timestamp}_{secure_filename(filename)}"
        file_path = f"{folder}/{unique_filename}"
        file_content = file.read()
        if len(file_content) > 50 * 1024 * 1024:
            logger.error(f"Arquivo muito grande: {len(file_content)} bytes")
            return None
        result = supabase_admin.storage.from_(BUCKET_NAME).upload(
            file_path,
            file_content,
            {"content-type": file.content_type}
        )
        if result:
            file_url = f"https://dkgzrqbzotwrskdmjxbw.supabase.co/storage/v1/object/public/{BUCKET_NAME}/{file_path}"
            logger.info(f"✅ Arquivo enviado para Supabase: {file_url}")
            return file_url
        else:
            logger.error("❌ Falha no upload para Supabase")
            return None
    except Exception as e:
        logger.error(f"❌ Erro ao fazer upload para Supabase: {str(e)}")
        return None

def salvar_media(file, media_type="imagem"):
    """
    Função MODIFICADA para converter vídeos para HLS.
    Para imagens/PDF: mantém o upload direto.
    Para vídeos: converte para HLS e retorna URL da playlist .m3u8.
    """
    if not file or file.filename == '':
        return None

    ALLOWED_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ALLOWED_VIDEO = {'mp4', 'webm', 'ogg', 'mov', 'avi', 'm4v'}
    ALLOWED_PDF = {'pdf'}

    filename = secure_filename(file.filename)
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    nome_unico = f"{timestamp}_{filename}"

    # --- Imagens e PDFs (direto) ---
    if file_ext in ALLOWED_IMAGE:
        folder = "imagens"
        file_path = f"{folder}/{nome_unico}"
        file_content = file.read()
        supabase_admin.storage.from_(BUCKET_NAME).upload(
            file_path,
            file_content,
            {"content-type": file.content_type}
        )
        return f"https://{SUPABASE_URL.split('//')[1]}/storage/v1/object/public/{BUCKET_NAME}/{file_path}"

    elif file_ext in ALLOWED_PDF:
        folder = "pdfs"
        file_path = f"{folder}/{nome_unico}"
        file_content = file.read()
        supabase_admin.storage.from_(BUCKET_NAME).upload(
            file_path,
            file_content,
            {"content-type": file.content_type}
        )
        return f"https://{SUPABASE_URL.split('//')[1]}/storage/v1/object/public/{BUCKET_NAME}/{file_path}"

    # --- Vídeos: CONVERSÃO HLS ---
    elif file_ext in ALLOWED_VIDEO:
        # Salva o vídeo original temporariamente
        with tempfile.NamedTemporaryFile(suffix=f".{file_ext}", delete=False) as tmp:
            file.save(tmp.name)
            caminho_original = tmp.name

        # Nome base sem extensão
        nome_base = nome_unico.rsplit('.', 1)[0]

        # Converte para HLS
        pasta_hls = converter_para_hls(caminho_original, nome_base)

        # Remove o vídeo original
        os.unlink(caminho_original)

        if not pasta_hls:
            logger.error("Falha na conversão HLS. Vídeo não será armazenado.")
            return None

        # Upload dos arquivos HLS
        prefixo_destino = f"videos/hls/{nome_base}"
        playlist_url = upload_pasta_hls(pasta_hls, prefixo_destino)
        return playlist_url

    else:
        logger.error(f"Tipo de arquivo não permitido: {file_ext}")
        return None

def deletar_do_supabase(file_url):
    """
    Função MODIFICADA para remover também pastas HLS completas.
    """
    try:
        if not file_url:
            return True

        if BUCKET_NAME in file_url and "storage/v1/object/public" in file_url:
            parts = file_url.split(f"object/public/{BUCKET_NAME}/")
            if len(parts) > 1:
                file_path = parts[1]

                # Se for uma playlist HLS, remove a pasta inteira
                if file_path.endswith('.m3u8'):
                    pasta = file_path.rsplit('/', 1)[0]
                    try:
                        arquivos = supabase_admin.storage.from_(BUCKET_NAME).list(pasta)
                        for arq in arquivos:
                            supabase_admin.storage.from_(BUCKET_NAME).remove([f"{pasta}/{arq['name']}"])
                        logger.info(f"✅ Pasta HLS removida: {pasta}")
                    except Exception as e:
                        logger.warning(f"Erro ao listar/remover pasta HLS: {e}")
                else:
                    supabase_admin.storage.from_(BUCKET_NAME).remove([file_path])
                    logger.info(f"✅ Arquivo removido: {file_path}")
                return True
        return False
    except Exception as e:
        logger.error(f"❌ Erro ao remover arquivo do Supabase: {str(e)}")
        return False

# ============================================
# CONEXÃO COM BANCO - OTIMIZADA COM POOL (100% igual)
# ============================================
db_pool = None

def init_db_pool():
    global db_pool
    try:
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            url = urlparse(database_url)
            db_pool = pool.SimpleConnectionPool(
                1, 10,
                database=url.path[1:],
                user=url.username,
                password=url.password,
                host=url.hostname,
                port=url.port,
                sslmode='require'
            )
        else:
            db_pool = pool.SimpleConnectionPool(
                1, 10,
                host="aws-1-sa-east-1.pooler.supabase.com",
                port=5432,
                database="postgres",
                user="postgres.dkgzrqbzotwrskdmjxbw",
                password="786*&%Mauq1",
                sslmode="require"
            )
        logger.info("✅ Pool de conexões inicializado com sucesso!")
        return True
    except Exception as e:
        logger.error(f"❌ Erro ao inicializar pool: {str(e)}")
        return False

def get_db_connection():
    try:
        if db_pool:
            return db_pool.getconn()
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            url = urlparse(database_url)
            return psycopg2.connect(
                database=url.path[1:],
                user=url.username,
                password=url.password,
                host=url.hostname,
                port=url.port,
                sslmode='require'
            )
        else:
            return psycopg2.connect(
                host="aws-1-sa-east-1.pooler.supabase.com",
                port=5432,
                database="postgres",
                user="postgres.dkgzrqbzotwrskdmjxbw",
                password="786*&%Mauq1",
                sslmode="require"
            )
    except Exception as e:
        logger.error(f"Erro na conexão com o banco: {str(e)}")
        return None

def release_db_connection(conn):
    try:
        if db_pool and conn:
            db_pool.putconn(conn)
        elif conn:
            conn.close()
    except Exception as e:
        logger.error(f"Erro ao liberar conexão: {str(e)}")

# ============================================
# FUNÇÕES AUXILIARES (100% iguais)
# ============================================
def criar_token(usuario_id):
    payload = {
        'user_id': usuario_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")

def verificar_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return payload.get('user_id')
    except Exception as e:
        logger.error(f"Erro ao verificar token: {str(e)}")
        return None

def validar_cpf(cpf):
    cpf = re.sub(r'\D', '', cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    soma = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digito1 = 0 if soma % 11 < 2 else 11 - (soma % 11)
    if digito1 != int(cpf[9]): return False
    soma = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digito2 = 0 if soma % 11 < 2 else 11 - (soma % 11)
    return digito2 == int(cpf[10])

def formatar_cpf(cpf):
    cpf = re.sub(r'\D', '', cpf)
    return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}" if len(cpf) == 11 else cpf

def get_usuario_by_email(email):
    conn = get_db_connection()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, email, senha, nome, cpf, google_id, data_criacao, ultimo_login, is_admin
            FROM usuarios WHERE email = %s AND ativo = TRUE
        """, (email,))
        row = cur.fetchone()
        if row:
            return {
                'id': row[0], 'email': row[1], 'senha': row[2], 'nome': row[3], 'cpf': row[4],
                'google_id': row[5], 'data_criacao': row[6], 'ultimo_login': row[7], 'is_admin': row[8] or False
            }
        return None
    finally:
        release_db_connection(conn)

def get_usuario_by_id(usuario_id):
    conn = get_db_connection()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, email, nome, cpf, google_id, data_criacao, ultimo_login, is_admin
            FROM usuarios WHERE id = %s AND ativo = TRUE
        """, (usuario_id,))
        row = cur.fetchone()
        if row:
            return {
                'id': row[0], 'email': row[1], 'nome': row[2], 'cpf': row[3],
                'google_id': row[4], 'data_criacao': row[5], 'ultimo_login': row[6], 'is_admin': row[7] or False
            }
        return None
    finally:
        release_db_connection(conn)

def atualizar_ultimo_login(usuario_id):
    conn = get_db_connection()
    if not conn: return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE usuarios SET ultimo_login = NOW() WHERE id = %s", (usuario_id,))
        conn.commit()
        return True
    finally:
        release_db_connection(conn)

def atualizar_cpf_usuario(usuario_id, cpf):
    conn = get_db_connection()
    if not conn: return False
    try:
        cur = conn.cursor()
        cur.execute("UPDATE usuarios SET cpf = %s WHERE id = %s", (cpf, usuario_id))
        conn.commit()
        return True
    finally:
        release_db_connection(conn)

# ============================================
# MIDDLEWARE DE AUTENTICAÇÃO (100% igual)
# ============================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        try:
            if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
                token = request.headers['Authorization'].split(" ")[1]
            elif 'token' in session:
                token = session['token']
            elif 'token' in request.args:
                token = request.args.get('token')
            if not token:
                return jsonify({'success': False, 'error': 'Token não fornecido'}), 401
            usuario_id = verificar_token(token)
            if not usuario_id:
                return jsonify({'success': False, 'error': 'Token inválido ou expirado'}), 401
            current_user = get_usuario_by_id(usuario_id)
            if not current_user:
                return jsonify({'success': False, 'error': 'Usuário não encontrado'}), 401
            request.current_user = current_user
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Erro no token_required: {str(e)}")
            return jsonify({'success': False, 'error': 'Erro de autenticação'}), 500
    return decorated

# ============================================
# INICIALIZAÇÃO DO BANCO (100% igual)
# ============================================
def verificar_e_corrigir_banco():
    logger.info("Verificando estrutura do banco de dados...")
    conn = get_db_connection()
    if not conn:
        logger.error("Não foi possível conectar ao banco")
        return False
    try:
        cur = conn.cursor()
        # Tabela de usuários
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                senha VARCHAR(255),
                nome VARCHAR(100) NOT NULL,
                cpf VARCHAR(14),
                google_id VARCHAR(255),
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ultimo_login TIMESTAMP,
                ativo BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE
            );
        """)
        # Tabela de compras
        cur.execute("""
            CREATE TABLE IF NOT EXISTS compras (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER NOT NULL,
                order_id VARCHAR(100) UNIQUE NOT NULL,
                valor DECIMAL(10,2) NOT NULL CHECK (valor > 0),
                status VARCHAR(50) NOT NULL DEFAULT 'pending',
                data_compra TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data_atualizacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                pix_code TEXT,
                qr_code_base64 TEXT,
                bolao_tipo VARCHAR(20),
                descricao TEXT,
                cartelas_compradas JSONB,
                quantidade INTEGER DEFAULT 1,
                jogos_gerados BOOLEAN DEFAULT FALSE,
                cotas_contabilizadas BOOLEAN DEFAULT FALSE,
                CONSTRAINT compras_usuario_id_fkey FOREIGN KEY (usuario_id) 
                REFERENCES usuarios(id) ON DELETE CASCADE
            );
        """)
        # Tabela de bolões
        cur.execute("""
            CREATE TABLE IF NOT EXISTS boloes (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(100) NOT NULL,
                cotas_totais INTEGER DEFAULT 100,
                cotas_vendidas INTEGER DEFAULT 0,
                vendidos INTEGER DEFAULT 100,
                ativo BOOLEAN DEFAULT TRUE,
                imagem_url TEXT,
                video_url TEXT,
                pdf_url TEXT,
                detalhes TEXT,
                preco DECIMAL(10,2) DEFAULT 1.00
            );
        """)
        # Adicionar colunas se não existirem
        colunas = [
            ('detalhes', 'TEXT'),
            ('vendidos', 'INTEGER DEFAULT 100'),
            ('preco', 'DECIMAL(10,2) DEFAULT 1.00'),
            ('video_url', 'TEXT'),
            ('pdf_url', 'TEXT')
        ]
        for coluna, tipo in colunas:
            cur.execute(f"""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='boloes' AND column_name='{coluna}'
            """)
            if not cur.fetchone():
                logger.info(f"Adicionando coluna '{coluna}' à tabela 'boloes'...")
                cur.execute(f"ALTER TABLE boloes ADD COLUMN {coluna} {tipo}")
        # Inserir bolões de exemplo se tabela vazia
        cur.execute("SELECT COUNT(*) FROM boloes")
        if cur.fetchone()[0] == 0:
            logger.info("Criando bolões de exemplo...")
            default_image = "https://dkgzrqbzotwrskdmjxbw.supabase.co/storage/v1/object/public/midia-concursos/imagens/default.jpg"
            cur.execute("""
                INSERT INTO boloes (nome, cotas_totais, imagem_url, detalhes, preco) 
                VALUES ('Concurso Exemplo Prefeitura', 100, %s, 'Apostila completa para concurso de prefeitura.', 1.00)
            """, (default_image,))
        # Índices
        indices = [
            ("idx_usuarios_email", "usuarios", "email"),
            ("idx_compras_usuario_id", "compras", "usuario_id"),
            ("idx_compras_order_id", "compras", "order_id"),
            ("idx_boloes_ativo", "boloes", "ativo"),
            ("idx_boloes_id_desc", "boloes", "id DESC")
        ]
        for idx_name, table, columns in indices:
            cur.execute(f"""
                SELECT 1 FROM pg_indexes 
                WHERE indexname = '{idx_name}'
            """)
            if not cur.fetchone():
                logger.info(f"Criando índice {idx_name}...")
                cur.execute(f"CREATE INDEX {idx_name} ON {table}({columns})")
        # Usuário admin
        admin_hash = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode('utf-8')
        cur.execute("""
            INSERT INTO usuarios (email, senha, nome, cpf, is_admin, data_criacao)
            VALUES ('admin@norteapostilas.com', %s, 'Administrador', '00000000000', TRUE, NOW())
            ON CONFLICT (email) DO UPDATE SET 
                senha = EXCLUDED.senha,
                is_admin = TRUE
        """, (admin_hash,))
        conn.commit()
        cur.close()
        logger.info("✅ Banco verificado e otimizado!")
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao verificar banco: {str(e)}")
        return False
    finally:
        release_db_connection(conn)

# ============================================
# ROTAS DE AUTENTICAÇÃO (100% iguais)
# ============================================
@app.route('/api/registrar', methods=['POST'])
def registrar():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'JSON requerido'}), 400
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        senha = data.get('senha', '')
        nome = data.get('nome', '').strip()
        if not all([email, senha, nome]) or '@' not in email or len(senha) < 6:
            return jsonify({'success': False, 'error': 'Dados inválidos'}), 400
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({'success': False, 'error': 'Email já cadastrado'}), 400
            hash_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cur.execute("INSERT INTO usuarios (email, senha, nome) VALUES (%s, %s, %s) RETURNING id", 
                       (email, hash_senha, nome))
            usuario_id = cur.fetchone()[0]
            conn.commit()
            token = criar_token(usuario_id)
            return jsonify({
                'success': True, 
                'token': token, 
                'usuario': {
                    'id': usuario_id, 
                    'email': email, 
                    'nome': nome, 
                    'is_admin': False
                }
            })
        finally:
            release_db_connection(conn)
    except Exception as e:
        logger.error(f"Erro no registro: {str(e)}")
        return jsonify({'success': False, 'error': 'Erro interno'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'JSON requerido'}), 400
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        senha = data.get('senha', '')
        usuario = get_usuario_by_email(email)
        if not usuario or not bcrypt.checkpw(senha.encode('utf-8'), usuario['senha'].encode('utf-8')):
            return jsonify({'success': False, 'error': 'Email ou senha incorretos'}), 401
        atualizar_ultimo_login(usuario['id'])
        token = criar_token(usuario['id'])
        return jsonify({
            'success': True,
            'token': token,
            'usuario': {
                'id': usuario['id'], 
                'email': usuario['email'], 
                'nome': usuario['nome'],
                'cpf': usuario['cpf'], 
                'is_admin': usuario['is_admin']
            }
        })
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        return jsonify({'success': False, 'error': 'Erro interno'}), 500

@app.route('/api/salvar-cpf', methods=['POST'])
@token_required
def salvar_cpf():
    data = request.get_json()
    cpf = re.sub(r'\D', '', data.get('cpf', ''))
    if not validar_cpf(cpf):
        return jsonify({'success': False, 'error': 'CPF inválido'}), 400
    if atualizar_cpf_usuario(request.current_user['id'], cpf):
        return jsonify({'success': True, 'cpf': formatar_cpf(cpf)})
    return jsonify({'success': False, 'error': 'Erro ao salvar'}), 500

@app.route('/api/usuario-atual', methods=['GET'])
@token_required
def usuario_atual():
    return jsonify({'success': True, 'usuario': request.current_user})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('token', None)
    return jsonify({'success': True})

# ============================================
# ROTAS PÚBLICAS (100% iguais)
# ============================================
@app.route('/api/boloes', methods=['GET'])
def listar_boloes():
    try:
        conn = get_db_connection()
        if not conn: 
            return jsonify({'success': False, 'error': 'Erro no banco'}), 500
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                id, nome, cotas_vendidas, cotas_totais,
                imagem_url, video_url, pdf_url, detalhes, 
                vendidos, preco
            FROM boloes 
            WHERE ativo = TRUE
            ORDER BY id DESC
            LIMIT 100
        """)
        rows = cur.fetchall()
        boloes_list = []
        for row in rows:
            bolao_id, nome, vendidas, total_cotas, imagem_url, video_url, pdf_url, detalhes, vendidos, preco = row
            boloes_list.append({
                'id': bolao_id,
                'nome': nome,
                'cotas_vendidas': vendidas or 0,
                'cotas_totais': total_cotas or 100,
                'imagem_url': imagem_url or 'https://dkgzrqbzotwrskdmjxbw.supabase.co/storage/v1/object/public/midia-concursos/imagens/default.jpg',
                'video_url': video_url,
                'pdf_url': pdf_url,
                'detalhes': detalhes or '',
                'vendidos': vendidos or 100,
                'preco': float(preco) if preco else 1.00
            })
        release_db_connection(conn)
        return jsonify({'success': True, 'boloes': boloes_list})
    except Exception as e:
        logger.error(f"Erro na rota /api/boloes: {str(e)}")
        return jsonify({'success': False, 'error': 'Erro interno no servidor'}), 500

@app.route('/api/health')
def health_check():
    conn = get_db_connection()
    db_status = "connected" if conn else "disconnected"
    if conn:
        release_db_connection(conn)
    supabase_status = "connected"
    try:
        supabase_admin.storage.list_buckets()
    except Exception as e:
        supabase_status = f"disconnected: {str(e)}"
    return jsonify({
        "status": "online", 
        "service": "Norte Apostilas", 
        "version": "1.4.0-hls",
        "database": db_status,
        "supabase": supabase_status,
        "storage": BUCKET_NAME,
        "project_id": "dkgzrqbzotwrskdmjxbw"
    })

# ============================================
# ROTAS QUE REQUEREM AUTENTICAÇÃO (100% iguais)
# ============================================
@app.route('/api/checkout', methods=['POST'])
@token_required
def checkout():
    try:
        if not request.is_json:
            return jsonify({"success": False, "error": "JSON requerido"}), 400
        data = request.get_json()
        if 'carrinho' not in data or not request.current_user.get('cpf'):
            return jsonify({"success": False, "error": "Dados inválidos ou CPF não cadastrado"}), 400
        bolao_id = data.get('bolao_id')
        quantidade = data.get('quantidade', 1)
        conn_preco = get_db_connection()
        preco_bolao = 1.00
        if conn_preco:
            try:
                cur_preco = conn_preco.cursor()
                cur_preco.execute("SELECT preco FROM boloes WHERE id = %s", (bolao_id,))
                result = cur_preco.fetchone()
                if result and result[0]:
                    preco_bolao = float(result[0])
            finally:
                release_db_connection(conn_preco)
        total = preco_bolao * quantidade
        conn_nome = get_db_connection()
        nome_bolao = "Apostila"
        if conn_nome:
            try:
                cur_nome = conn_nome.cursor()
                cur_nome.execute("SELECT nome FROM boloes WHERE id = %s", (bolao_id,))
                result = cur_nome.fetchone()
                if result:
                    nome_bolao = result[0]
            finally:
                release_db_connection(conn_nome)
        descricao = f"{nome_bolao} - {quantidade} unidade{'s' if quantidade > 1 else ''}"
        cpf_usuario = re.sub(r'\D', '', request.current_user['cpf'])
        payment_data = {
            "transaction_amount": float(total),
            "description": descricao,
            "payment_method_id": "pix",
            "payer": {
                "email": request.current_user['email'],
                "first_name": request.current_user['nome'].split()[0],
                "identification": {"type": "CPF", "number": cpf_usuario}
            }
        }
        result = sdk.payment().create(payment_data)
        if 'response' not in result:
            return jsonify({"success": False, "error": "Erro no Mercado Pago"}), 500
        payment = result["response"]
        pix_data = payment.get("point_of_interaction", {}).get("transaction_data", {})
        pix_code = pix_data.get("qr_code", "")
        qr_code_base64 = pix_data.get("qr_code_base64", "")
        cartelas_compradas = data.get('cartelas', [])
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO compras (
                    usuario_id, order_id, valor, status, pix_code, qr_code_base64,
                    descricao, cartelas_compradas, quantidade, cotas_contabilizadas
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE)
            """, (
                request.current_user['id'], str(payment['id']), total, payment.get('status', 'pending'),
                pix_code, qr_code_base64, descricao, json.dumps(cartelas_compradas), quantidade
            ))
            conn.commit()
        finally:
            release_db_connection(conn)
        return jsonify({
            "success": True,
            "order_id": payment["id"],
            "pix_code": pix_code,
            "pix_qr_base64": qr_code_base64,
            "valor": total
        })
    except Exception as e:
        logger.error(f"ERRO NO CHECKOUT: {str(e)}")
        return jsonify({"success": False, "error": "Erro interno"}), 500

@app.route('/api/status/<order_id>')
@token_required
def check_status(order_id):
    try:
        result = sdk.payment().get(order_id)
        payment = result["response"]
        status = payment.get("status", "unknown")
        conn = get_db_connection()
        if not conn:
            return jsonify({"success": False, "error": "Erro no banco"}), 500
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT descricao, quantidade, cotas_contabilizadas, status 
                FROM compras 
                WHERE order_id = %s AND usuario_id = %s
            """, (order_id, request.current_user['id']))
            compra_info = cur.fetchone()
            if compra_info:
                descricao, quantidade, cotas_contabilizadas, status_atual = compra_info
                bolao_nome = descricao.split(' - ')[0] if ' - ' in descricao else descricao
                cur.execute("SELECT id FROM boloes WHERE nome = %s", (bolao_nome,))
                bolao_result = cur.fetchone()
                if status == 'approved' and not cotas_contabilizadas and bolao_result:
                    bolao_id = bolao_result[0]
                    cur.execute("""
                        UPDATE boloes 
                        SET cotas_vendidas = cotas_vendidas + %s 
                        WHERE id = %s
                    """, (quantidade, bolao_id))
                    cur.execute("""
                        UPDATE compras 
                        SET cotas_contabilizadas = TRUE 
                        WHERE order_id = %s
                    """, (order_id,))
                cur.execute("""
                    UPDATE compras 
                    SET status = %s, data_atualizacao = NOW()
                    WHERE order_id = %s AND usuario_id = %s
                    RETURNING valor, pix_code, qr_code_base64, descricao
                """, (status, order_id, request.current_user['id']))
                updated = cur.fetchone()
                conn.commit()
                if updated and status == 'pending':
                    return jsonify({
                        "success": True,
                        "status": "pending",
                        "valor": float(updated[0]),
                        "pix_code": updated[1],
                        "qr_code_base64": updated[2],
                        "descricao": updated[3]
                    })
            return jsonify({"success": True, "status": status})
        finally:
            release_db_connection(conn)
    except Exception as e:
        logger.error(f"Erro ao verificar status: {str(e)}")
        return jsonify({"success": False, "error": "Erro ao verificar"}), 500

@app.route('/api/compras-usuario', methods=['GET'])
@token_required
def compras_usuario():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT order_id, valor, status, data_compra, descricao, quantidade
                FROM compras 
                WHERE usuario_id = %s 
                ORDER BY data_compra DESC
            """, (request.current_user['id'],))
            rows = cur.fetchall()
            compras = []
            for row in rows:
                descricao = row[4] or 'Apostila'
                bolao_nome = descricao.split(' - ')[0] if ' - ' in descricao else descricao
                pdf_url = None
                try:
                    cur.execute("SELECT pdf_url FROM boloes WHERE nome = %s", (bolao_nome,))
                    pdf_result = cur.fetchone()
                    if pdf_result:
                        pdf_url = pdf_result[0]
                except Exception as e:
                    logger.error(f"Erro ao buscar PDF: {e}")
                compras.append({
                    'order_id': row[0],
                    'valor': float(row[1]) if row[1] else 0.0,
                    'status': row[2] or 'pending',
                    'data_compra': row[3].isoformat() if row[3] else None,
                    'descricao': descricao,
                    'quantidade': row[5] or 1,
                    'pdf_url': pdf_url
                })
            return jsonify({'success': True, 'compras': compras})
        finally:
            release_db_connection(conn)
    except Exception as e:
        logger.error(f"Erro ao carregar compras: {str(e)}")
        return jsonify({'success': False, 'error': f'Erro interno: {str(e)}'}), 500

# ============================================
# ROTAS ADMIN (100% iguais)
# ============================================
@app.route('/api/admin/criar-bolao', methods=['POST'])
@token_required
def admin_criar_bolao():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    imagem_url = None
    video_url = None
    pdf_url = None
    if 'imagem' in request.files and request.files['imagem'].filename != '':
        file = request.files['imagem']
        imagem_url = salvar_media(file, "imagem")
    if 'video' in request.files and request.files['video'].filename != '':
        file = request.files['video']
        video_url = salvar_media(file, "video")
    if 'pdf' in request.files and request.files['pdf'].filename != '':
        file = request.files['pdf']
        pdf_url = salvar_media(file, "pdf")
    if not imagem_url and not video_url:
        return jsonify({'success': False, 'error': 'Adicione pelo menos uma imagem ou vídeo'}), 400
    nome = request.form.get('nome', '').strip()
    detalhes = request.form.get('detalhes', '').strip()
    vendidos = request.form.get('vendidos', '100').strip()
    preco = request.form.get('preco', '1.00').strip()
    if not nome:
        return jsonify({'success': False, 'error': 'Nome é obrigatório'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM boloes WHERE nome = %s", (nome,))
        if cur.fetchone():
            return jsonify({'success': False, 'error': 'Já existe um concurso com este nome'}), 400
        cotas_totais = 100
        vendidos_int = int(vendidos) if vendidos.isdigit() else 100
        preco_float = float(preco) if preco.replace('.', '', 1).isdigit() else 1.00
        cur.execute("""
            INSERT INTO boloes (nome, cotas_totais, imagem_url, video_url, pdf_url, detalhes, vendidos, preco)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (nome, cotas_totais, imagem_url, video_url, pdf_url, detalhes, vendidos_int, preco_float))
        conn.commit()
        return jsonify({
            'success': True, 
            'message': 'Concurso criado com sucesso!',
            'imagem_url': imagem_url,
            'video_url': video_url,
            'pdf_url': pdf_url
        })
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao criar bolão: {e}")
        return jsonify({'success': False, 'error': 'Erro ao salvar concurso'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/admin/boloes', methods=['GET'])
@token_required
def admin_listar_boloes():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, nome, cotas_totais, cotas_vendidas, vendidos, ativo, imagem_url, video_url, pdf_url, detalhes, preco
            FROM boloes 
            ORDER BY id DESC
        """)
        rows = cur.fetchall()
        boloes = []
        for row in rows:
            boloes.append({
                'id': row[0],
                'nome': row[1],
                'cotas_totais': row[2],
                'cotas_vendidas': row[3] or 0,
                'vendidos': row[4] or 100,
                'ativo': row[5],
                'imagem_url': row[6] or 'https://dkgzrqbzotwrskdmjxbw.supabase.co/storage/v1/object/public/midia-concursos/imagens/default.jpg',
                'video_url': row[7],
                'pdf_url': row[8],
                'detalhes': row[9] or '',
                'preco': float(row[10]) if row[10] else 1.00
            })
        return jsonify({'success': True, 'boloes': boloes})
    except Exception as e:
        logger.error(f"Erro ao listar bolões admin: {e}")
        return jsonify({'success': False, 'error': 'Erro interno'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/admin/editar-bolao', methods=['POST'])
@token_required
def admin_editar_bolao():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    bolao_id = request.form.get('id')
    nome = request.form.get('nome', '').strip()
    cotas_totais = int(request.form.get('qtd_cotas', 100))
    vendidos = request.form.get('vendidos', '100').strip()
    detalhes = request.form.get('detalhes', '').strip()
    preco = request.form.get('preco', '1.00').strip()
    if not bolao_id or not nome or cotas_totais < 1:
        return jsonify({'success': False, 'error': 'Dados inválidos'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT cotas_vendidas, imagem_url, video_url, pdf_url FROM boloes WHERE id = %s
        """, (bolao_id,))
        resultado = cur.fetchone()
        if not resultado:
            return jsonify({'success': False, 'error': 'Concurso não encontrado'}), 404
        cotas_vendidas, current_imagem, current_video, current_pdf = resultado
        if cotas_totais < cotas_vendidas:
            return jsonify({
                'success': False, 
                'error': f'Não é possível reduzir para {cotas_totais} cotas. Já foram vendidas {cotas_vendidas}.'
            }), 400
        nova_imagem_url = current_imagem
        nova_video_url = current_video
        nova_pdf_url = current_pdf
        if 'imagem' in request.files and request.files['imagem'].filename != '':
            nova = salvar_media(request.files['imagem'], "imagem")
            if nova:
                nova_imagem_url = nova
                if current_imagem and 'default.jpg' not in current_imagem:
                    deletar_do_supabase(current_imagem)
        if 'video' in request.files and request.files['video'].filename != '':
            nova = salvar_media(request.files['video'], "video")
            if nova:
                nova_video_url = nova
                if current_video:
                    deletar_do_supabase(current_video)
        if 'pdf' in request.files and request.files['pdf'].filename != '':
            file = request.files['pdf']
            if file and file.filename.lower().endswith('.pdf'):
                nova = salvar_media(file, "pdf")
                if nova:
                    nova_pdf_url = nova
                    if current_pdf:
                        deletar_do_supabase(current_pdf)
        if not nova_imagem_url and not nova_video_url:
            return jsonify({'success': False, 'error': 'É necessário ter pelo menos uma imagem ou vídeo'}), 400
        cur.execute("SELECT id FROM boloes WHERE nome = %s AND id != %s", (nome, bolao_id))
        if cur.fetchone():
            return jsonify({'success': False, 'error': 'Já existe um concurso com este nome'}), 400
        vendidos_int = int(vendidos) if vendidos.isdigit() else 100
        preco_float = float(preco) if preco.replace('.', '', 1).isdigit() else 1.00
        cur.execute("""
            UPDATE boloes 
            SET nome = %s, cotas_totais = %s, imagem_url = %s, video_url = %s, 
                pdf_url = %s, detalhes = %s, vendidos = %s, preco = %s
            WHERE id = %s
        """, (nome, cotas_totais, nova_imagem_url, nova_video_url, 
              nova_pdf_url, detalhes, vendidos_int, preco_float, bolao_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Concurso atualizado com sucesso!'})
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao editar bolão: {e}")
        return jsonify({'success': False, 'error': 'Erro ao atualizar concurso'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/admin/atualizar-vendidos', methods=['POST'])
@token_required
def admin_atualizar_vendidos():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    data = request.get_json()
    bolao_id = data.get('bolao_id')
    vendidos = data.get('vendidos')
    if not bolao_id or vendidos is None:
        return jsonify({'success': False, 'error': 'Dados inválidos'}), 400
    try:
        vendidos_int = int(vendidos)
        if vendidos_int < 0:
            return jsonify({'success': False, 'error': 'Valor de vendidos não pode ser negativo'}), 400
    except ValueError:
        return jsonify({'success': False, 'error': 'Valor de vendidos inválido'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM boloes WHERE id = %s", (bolao_id,))
        if not cur.fetchone():
            return jsonify({'success': False, 'error': 'Concurso não encontrado'}), 404
        cur.execute("""
            UPDATE boloes 
            SET vendidos = %s 
            WHERE id = %s
        """, (vendidos_int, bolao_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Vendidos atualizados com sucesso!'})
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao atualizar vendidos: {e}")
        return jsonify({'success': False, 'error': 'Erro ao atualizar vendidos'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/admin/remover-bolao/<int:bolao_id>', methods=['DELETE'])
@token_required
def admin_remover_bolao(bolao_id):
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT imagem_url, video_url, pdf_url FROM boloes WHERE id = %s
        """, (bolao_id,))
        resultado = cur.fetchone()
        if not resultado:
            return jsonify({'success': False, 'error': 'Concurso não encontrado'}), 404
        imagem_url, video_url, pdf_url = resultado
        cur.execute("DELETE FROM boloes WHERE id = %s", (bolao_id,))
        for url in [imagem_url, video_url, pdf_url]:
            if url and 'default.jpg' not in url:
                deletar_do_supabase(url)
        conn.commit()
        return jsonify({'success': True, 'message': 'Concurso removido com sucesso!'})
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao remover bolão: {e}")
        return jsonify({'success': False, 'error': 'Erro ao remover concurso'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/admin/compras-todos-usuarios', methods=['GET'])
@token_required
def admin_compras_todos():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT c.order_id, c.valor, c.status, c.data_compra, c.descricao, c.quantidade, u.email, u.nome
            FROM compras c JOIN usuarios u ON c.usuario_id = u.id
            ORDER BY c.data_compra DESC
        """)
        compras = []
        for r in cur.fetchall():
            compras.append({
                'order_id': r[0], 'valor': float(r[1]), 'status': r[2], 'data_compra': r[3].isoformat() if r[3] else None,
                'descricao': r[4] or 'Apostila', 'quantidade': r[5] or 1, 'usuario_email': r[6], 'usuario_nome': r[7]
            })
        return jsonify({'success': True, 'compras': compras})
    finally:
        release_db_connection(conn)

@app.route('/api/admin/corrigir-cotas', methods=['POST'])
@token_required
def corrigir_cotas():
    if not request.current_user.get('is_admin', False):
        return jsonify({'success': False, 'error': 'Acesso negado'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    try:
        cur = conn.cursor()
        cur.execute("UPDATE boloes SET cotas_vendidas = 0")
        cur.execute("""
            SELECT c.descricao, c.quantidade 
            FROM compras c 
            WHERE c.status = 'approved' AND c.cotas_contabilizadas = FALSE
        """)
        compras_aprovadas = cur.fetchall()
        for descricao, quantidade in compras_aprovadas:
            if ' - ' in descricao:
                bolao_nome = descricao.split(' - ')[0]
                cur.execute("""
                    UPDATE boloes 
                    SET cotas_vendidas = cotas_vendidas + %s 
                    WHERE nome = %s
                """, (quantidade, bolao_nome))
        cur.execute("""
            UPDATE compras 
            SET cotas_contabilizadas = CASE 
                WHEN status = 'approved' THEN TRUE 
                ELSE FALSE 
            END
        """)
        conn.commit()
        return jsonify({
            'success': True, 
            'message': 'Cotas corrigidas com sucesso!'
        })
    except Exception as e:
        conn.rollback()
        logger.error(f"Erro ao corrigir cotas: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        release_db_connection(conn)

# ============================================
# ROTAS FRONTEND (100% iguais)
# ============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
@token_required
def painel_admin():
    if not request.current_user.get('is_admin', False):
        abort(403)
    return render_template('admin.html')

@app.route('/teste-db')
def teste_db():
    conn = get_db_connection()
    if not conn:
        return "Erro de conexão", 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT version()")
        version = cur.fetchone()[0]
        return f"Conectado! Versão: {version}"
    finally:
        release_db_connection(conn)

# ============================================
# ROTAS DO SUPABASE (PARA TESTE)
# ============================================
@app.route('/api/supabase-test', methods=['GET'])
def supabase_test():
    try:
        buckets = supabase_admin.storage.list_buckets()
        files = supabase_admin.storage.from_(BUCKET_NAME).list()
        return jsonify({
            'success': True,
            'project_id': 'dkgzrqbzotwrskdmjxbw',
            'buckets': [b.name for b in buckets],
            'files_count': len(files) if files else 0,
            'files_sample': files[:5] if files else [],
            'bucket_name': BUCKET_NAME,
            'status': 'Conectado ao Supabase Storage',
            'url_example': 'https://dkgzrqbzotwrskdmjxbw.supabase.co/storage/v1/object/public/midia-concursos/imagens/default.jpg'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'status': 'Erro ao conectar ao Supabase'
        }), 500

# ============================================
# INICIALIZAÇÃO DO APLICATIVO
# ============================================
def inicializar_aplicacao():
    logger.info("=== NORTE APOSTILAS - SISTEMA DE VENDAS (HLS STREAMING) ===")
    logger.info(f"Project ID: dkgzrqbzotwrskdmjxbw")
    logger.info("Inicializando pool de conexões...")
    if not init_db_pool():
        logger.warning("⚠️  Pool não inicializado, usando conexões diretas")
    logger.info("Inicializando Supabase Storage...")
    if inicializar_supabase_storage():
        logger.info("✅ Supabase Storage inicializado com sucesso!")
    else:
        logger.warning("⚠️  Aviso: Houve problemas ao inicializar Supabase Storage.")
    logger.info("Verificando estrutura do banco de dados...")
    if verificar_e_corrigir_banco():
        logger.info("✅ Banco de dados verificado e otimizado!")
    else:
        logger.warning("⚠️  Aviso: Houve problemas ao verificar o banco de dados.")
    # Verificar FFmpeg
    if verificar_ffmpeg():
        logger.info("✅ FFmpeg disponível - conversão HLS ativada")
    else:
        logger.error("❌ FFmpeg NÃO encontrado! Vídeos não poderão ser convertidos para HLS.")
        logger.error("   Instale via aptfile no Render.")
    logger.info("✅ Aplicação inicializada com sucesso!")
    logger.info("✅ Vídeos serão convertidos para HLS e armazenados no Supabase")
    logger.info("Login Admin: admin@norteapostilas.com / senha: admin123")

inicializar_aplicacao()

# ============================================
# PONTO DE ENTRADA PARA RENDER
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)