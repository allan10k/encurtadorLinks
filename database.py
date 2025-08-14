# database.py - VERSÃO COMPLETA E ATUALIZADA

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='básico')
    
    # NOVA COLUNA: Controla se o usuário deve ser forçado a redefinir a senha no próximo login.
    # O padrão é False, mas será True quando um novo usuário for criado pelo admin.
    precisa_resetar_senha = db.Column(db.Boolean, default=False, nullable=False)

    links = db.relationship('Link', backref='creator', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(512), nullable=False)
    short_code = db.Column(db.String(10), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    clicks = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # NOVA RELAÇÃO: Conecta o Link aos seus dados de clique.
    # Se um Link for deletado, todos os seus dados de clique também serão (cascade).
    clicks_data = db.relationship('Click', backref='link', lazy=True, cascade="all, delete-orphan")


# NOVA TABELA: Para armazenar os detalhes de cada clique
class Click(db.Model):
    """
    Define a estrutura da tabela de estatísticas de cliques.
    """
    id = db.Column(db.Integer, primary_key=True)
    # Chave estrangeira para associar o clique a um link específico
    link_id = db.Column(db.Integer, db.ForeignKey('link.id'), nullable=False)
    ip_address = db.Column(db.String(45)) # Armazena o endereço IP (suporta IPv4 e IPv6)
    user_agent = db.Column(db.String(255)) # Armazena informações do navegador
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow) # Data e hora do clique