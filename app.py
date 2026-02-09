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
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, session, abort, send_from_directory
from flask_cors import CORS
from functools import wraps, lru_cache
from werkzeug.utils import secure_filename

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

# NO RENDER: Use variável de ambiente para secret_key
app.secret_key = os.environ.get('SECRET_KEY', 'lotomaster_sistema_boloes_2024_seguro')
app.config['UPLOAD_FOLDER'] = imagens_dir
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
CORS(app, supports_credentials=True)

# ============================================
# CONEXÃO COM BANCO - OTIMIZADA COM POOL
# ============================================
db_pool = None

def init_db_pool():
    """Inicializa pool de conexões para melhor performance"""
    global db_pool
    try:
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            url = urlparse(database_url)
            db_pool = pool.SimpleConnectionPool(
                1, 10,  # min e max conexões
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
    """Obtém conexão do pool"""
    try:
        if db_pool:
            return db_pool.getconn()
        
        # Fallback sem pool
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
    """Devolve conexão ao pool"""
    try:
        if db_pool and conn:
            db_pool.putconn(conn)
        elif conn:
            conn.close()
    except Exception as e:
        logger.error(f"Erro ao liberar conexão: {str(e)}")

# ============================================
# MERCADO PAGO - ADAPTADO PARA RENDER
# ============================================
ACCESS_TOKEN = os.environ.get('MERCADO_PAGO_ACCESS_TOKEN', 'APP_USR-6894468649991242-122722-f91f76096569c694ed26cc237ebd084c-3097500632')
sdk = mercadopago.SDK(ACCESS_TOKEN)

# ============================================
# FUNÇÕES AUXILIARES (PERMANECEM IGUAIS)
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
# MIDDLEWARE DE AUTENTICAÇÃO
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
# UPLOAD DE MÍDIA
# ============================================
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'ogg', 'mov', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def salvar_media(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return f"/static/imagens_boloes/{filename}"
    return None

# ============================================
# INICIALIZAÇÃO DO BANCO
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
            cur.execute("""
                INSERT INTO boloes (nome, cotas_totais, imagem_url, detalhes, preco) 
                VALUES ('Concurso Exemplo Prefeitura', 100, '/static/imagens_boloes/default.jpg', 'Apostila completa para concurso de prefeitura.', 1.00)
            """)
        
        # ===== OTIMIZAÇÃO CRÍTICA: ÍNDICES =====
        logger.info("Criando índices de performance...")
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
            VALUES ('admin@lotomaster.com', %s, 'Administrador', '00000000000', TRUE, NOW())
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
# ROTAS DE AUTENTICAÇÃO
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
# ROTAS PÚBLICAS (SEM AUTENTICAÇÃO)
# ============================================

# ===== OTIMIZAÇÃO CRÍTICA: ROTA /api/boloes MAIS RÁPIDA =====
@app.route('/api/boloes', methods=['GET'])
def listar_boloes():
    """ROTA PÚBLICA OTIMIZADA - Mais rápida"""
    import time
    start_time = time.time()
    
    conn = get_db_connection()
    if not conn: 
        logger.error("❌ Erro: Não conseguiu conectar ao banco")
        return jsonify({'success': False, 'error': 'Erro no banco'}), 500
    
    try:
        cur = conn.cursor()
        
        # ===== QUERY OTIMIZADA: Uma única query eficiente =====
        query = """
            SELECT 
                id, nome, cotas_vendidas, cotas_totais,
                imagem_url, video_url, pdf_url, detalhes, 
                vendidos, preco
            FROM boloes 
            WHERE ativo = TRUE
            ORDER BY id DESC
            LIMIT 100
        """
        
        logger.info(f"⏱️  Executando query...")
        query_start = time.time()
        cur.execute(query)
        rows = cur.fetchall()
        query_time = time.time() - query_start
        logger.info(f"✅ Query executada em {query_time:.3f}s - {len(rows)} bolões encontrados")
        
        # ===== PROCESSAMENTO OTIMIZADO =====
        boloes_list = []
        for row in rows:
            bolao_id, nome, vendidas, total_cotas, imagem_url, video_url, pdf_url, detalhes, vendidos, preco = row
            
            boloes_list.append({
                'id': bolao_id,
                'nome': nome,
                'cotas_vendidas': vendidas or 0,
                'cotas_totais': total_cotas or 100,
                'imagem_url': imagem_url or '/static/imagens_boloes/default.jpg',
                'video_url': video_url,
                'pdf_url': pdf_url,
                'detalhes': detalhes or '',
                'vendidos': vendidos or 100,
                'preco': float(preco) if preco else 1.00
            })
        
        total_time = time.time() - start_time
        logger.info(f"✅ Resposta /api/boloes completa em {total_time:.3f}s")
        
        return jsonify({'success': True, 'boloes': boloes_list})
    
    except Exception as e:
        logger.error(f"❌ Erro na rota /api/boloes: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Erro interno no servidor'}), 500
    finally:
        release_db_connection(conn)

@app.route('/api/health')
def health_check():
    """ROTA PÚBLICA - Health check"""
    conn = get_db_connection()
    db_status = "connected" if conn else "disconnected"
    if conn:
        release_db_connection(conn)
    
    return jsonify({
        "status": "online", 
        "service": "Norte Apostilas", 
        "version": "1.1.0-optimized",
        "database": db_status
    })

# ============================================
# ROTAS QUE REQUEREM AUTENTICAÇÃO
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
# ROTAS ADMIN (mantidas iguais, só trocando conn.close() por release_db_connection())
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
        imagem_url = salvar_media(file)

    if 'video' in request.files and request.files['video'].filename != '':
        file = request.files['video']
        video_url = salvar_media(file)

    if 'pdf' in request.files and request.files['pdf'].filename != '':
        file = request.files['pdf']
        if file and file.filename.lower().endswith('.pdf'):
            pdf_url = salvar_media(file)

    if not imagem_url and not video_url:
        return jsonify({'success': False, 'error': 'Adicione pelo menos uma imagem ou vídeo'}), 400

    nome = request.form.get('nome', '').strip()
    detalhes = request.form.get('detalhes', '').strip()
    vendidos = request.form.get('vendidos', '100').strip()
    preco = request.form.get('preco', '1.00').strip()

    if not nome:
        for url in [imagem_url, video_url, pdf_url]:
            if url:
                try:
                    filename = url.split('/')[-1]
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                except:
                    pass
        return jsonify({'success': False, 'error': 'Nome é obrigatório'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Erro no banco de dados'}), 500
    
    try:
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM boloes WHERE nome = %s", (nome,))
        if cur.fetchone():
            for url in [imagem_url, video_url, pdf_url]:
                if url:
                    try:
                        filename = url.split('/')[-1]
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    except:
                        pass
            return jsonify({'success': False, 'error': 'Já existe um concurso com este nome'}), 400
        
        cotas_totais = 100
        vendidos_int = int(vendidos) if vendidos.isdigit() else 100
        preco_float = float(preco) if preco.replace('.', '', 1).isdigit() else 1.00
        
        cur.execute("""
            INSERT INTO boloes (nome, cotas_totais, imagem_url, video_url, pdf_url, detalhes, vendidos, preco)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (nome, cotas_totais, imagem_url, video_url, pdf_url, detalhes, vendidos_int, preco_float))
        conn.commit()
        return jsonify({'success': True, 'message': 'Concurso criado com sucesso!'})
    except Exception as e:
        conn.rollback()
        for url in [imagem_url, video_url, pdf_url]:
            if url:
                try:
                    filename = url.split('/')[-1]
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                except:
                    pass
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
                'imagem_url': row[6] or '/static/imagens_boloes/default.jpg',
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
            nova = salvar_media(request.files['imagem'])
            if nova:
                nova_imagem_url = nova
                if current_imagem and 'default.jpg' not in current_imagem:
                    try:
                        old_file = current_imagem.split('/')[-1]
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_file))
                    except Exception as e:
                        logger.error(f"Erro ao remover imagem antiga: {e}")

        if 'video' in request.files and request.files['video'].filename != '':
            nova = salvar_media(request.files['video'])
            if nova:
                nova_video_url = nova
                if current_video:
                    try:
                        old_file = current_video.split('/')[-1]
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_file))
                    except Exception as e:
                        logger.error(f"Erro ao remover vídeo antigo: {e}")

        if 'pdf' in request.files and request.files['pdf'].filename != '':
            file = request.files['pdf']
            if file and file.filename.lower().endswith('.pdf'):
                nova = salvar_media(file)
                if nova:
                    nova_pdf_url = nova
                    if current_pdf:
                        try:
                            old_file = current_pdf.split('/')[-1]
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_file))
                        except Exception as e:
                            logger.error(f"Erro ao remover PDF antigo: {e}")

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
                try:
                    filename = url.split('/')[-1]
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as e:
                    logger.error(f"Erro ao remover arquivo: {e}")
        
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
# ROTAS FRONTEND
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

@app.route('/static/imagens_boloes/<filename>')
def servir_imagem(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
# INICIALIZAÇÃO DO APLICATIVO
# ============================================

def inicializar_aplicacao():
    logger.info("=== NORTE APOSTILAS - SISTEMA DE VENDAS (OTIMIZADO) ===")
    logger.info("Inicializando pool de conexões...")
    
    if not init_db_pool():
        logger.warning("⚠️  Pool não inicializado, usando conexões diretas")
    
    logger.info("Verificando estrutura do banco de dados...")
    if verificar_e_corrigir_banco():
        logger.info("✅ Banco de dados verificado e otimizado!")
    else:
        logger.warning("⚠️  Aviso: Houve problemas ao verificar o banco de dados.")
    
    logger.info("✅ Aplicação inicializada com sucesso!")
    logger.info("Login Admin: admin@lotomaster.com / senha: admin123")

# Inicializar ao iniciar a aplicação
inicializar_aplicacao()

# ============================================
# PONTO DE ENTRADA PARA RENDER
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)