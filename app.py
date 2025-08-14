# app.py - VERSÃO COM A CORREÇÃO FINAL DO FUSO HORÁRIO DE EXPIRAÇÃO

from functools import wraps
import string
import random
from datetime import datetime
import io
import csv
import qrcode
from PIL import Image
import base64
import os
import uuid
import click
import pytz # Importação necessária
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from database import db, User, Link, Click
from weasyprint import HTML
from werkzeug.utils import secure_filename


# --- CONFIGURAÇÃO INICIAL DA APLICAÇÃO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-super-segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

db.init_app(app)

# --- CONFIGURAÇÃO DE FUSO HORÁRIO ---
BR_TIMEZONE = pytz.timezone('America/Sao_Paulo')

# --- FUNÇÃO E FILTRO JINJA PARA FORMATAR DATAS ---
def format_datetime_brt(utc_dt, fmt='%d/%m/%Y %H:%M'):
    if utc_dt is None:
        return ''
    # Garante que a data do banco (que é "naive") seja tratada como UTC
    if utc_dt.tzinfo is None:
        utc_dt = pytz.utc.localize(utc_dt)
    # Converte para o fuso horário de Brasília
    brt_dt = utc_dt.astimezone(BR_TIMEZONE)
    return brt_dt.strftime(fmt)

app.jinja_env.filters['datetime_brt'] = format_datetime_brt


# --- CONFIGURAÇÃO DO SISTEMA DE LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DECORATOR PARA PROTEGER ROTAS DE ADMIN ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Acesso negado. Você precisa ser um administrador para ver esta página.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# --- ROTAS DA APLICAÇÃO (PÁGINAS) ---
@app.route('/')
@login_required
def index():
    if current_user.precisa_resetar_senha:
        flash('Você precisa redefinir sua senha antes de continuar.', 'warning')
        return redirect(url_for('redefinir_senha'))
    
    sort_by = request.args.get('sort_by', 'data')
    if sort_by == 'cliques':
        query = Link.query.order_by(Link.clicks.desc())
    else:
        query = Link.query.order_by(Link.created_at.desc())
    
    links = query.all()
    return render_template('index.html', links=links, sort_by=sort_by)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Usuário ou senha inválidos.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        if user.precisa_resetar_senha:
            flash('Este é seu primeiro acesso ou sua senha foi resetada. Por favor, crie uma nova senha.', 'info')
            return redirect(url_for('redefinir_senha'))
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/redefinir-senha', methods=['GET', 'POST'])
@login_required
def redefinir_senha():
    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']
        if not nova_senha or not confirmar_senha:
            flash('Ambos os campos de senha são obrigatórios.', 'danger')
            return redirect(url_for('redefinir_senha'))
        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('redefinir_senha'))
        current_user.set_password(nova_senha)
        current_user.precisa_resetar_senha = False
        db.session.commit()
        flash('Senha redefinida com sucesso! Você já pode usar o sistema.', 'success')
        return redirect(url_for('index'))
    return render_template('redefinir_senha.html')


# --- ROTAS DO ENCURTADOR ---
def gerar_codigo_curto(tamanho=6):
    caracteres = string.ascii_letters + string.digits
    while True:
        codigo = ''.join(random.choices(caracteres, k=tamanho))
        if not Link.query.filter_by(short_code=codigo).first(): return codigo

@app.route('/encurtar', methods=['POST'])
@login_required
def encurtar_link():
    url_original = request.form['url_original']
    codigo_personalizado = request.form.get('codigo_personalizado')
    data_expiracao_str = request.form.get('data_expiracao')
    if not url_original:
        flash('A URL original é obrigatória.', 'danger')
        return redirect(url_for('index'))
    codigo_final = ""
    if codigo_personalizado:
        if Link.query.filter_by(short_code=codigo_personalizado).first():
            flash('Este código personalizado já está em uso. Tente outro.', 'warning')
            return redirect(url_for('index'))
        codigo_final = codigo_personalizado
    else:
        codigo_final = gerar_codigo_curto()
    data_expiracao = None
    if data_expiracao_str:
        try:
            # Lógica de conversão de fuso horário correta
            naive_datetime = datetime.strptime(data_expiracao_str, '%Y-%m-%dT%H:%M')
            brt_datetime = BR_TIMEZONE.localize(naive_datetime)
            data_expiracao = brt_datetime.astimezone(pytz.utc)
        except ValueError:
            flash('Formato de data e hora inválido.', 'danger')
            return redirect(url_for('index'))
    novo_link = Link(original_url=url_original, short_code=codigo_final, user_id=current_user.id, expires_at=data_expiracao)
    db.session.add(novo_link)
    db.session.commit()
    flash('Link encurtado com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/<string:short_code>')
def redirecionar(short_code):
    link = Link.query.filter_by(short_code=short_code).first_or_404()
    # A comparação agora é correta: compara a hora atual em UTC com a hora de expiração (também em UTC)
    if link.expires_at and datetime.utcnow() > link.expires_at:
        return render_template('link_expirado.html'), 404
    link.clicks += 1
    novo_clique = Click(link_id=link.id, ip_address=request.remote_addr, user_agent=request.user_agent.string)
    db.session.add(novo_clique)
    db.session.commit()
    return redirect(link.original_url)

@app.route('/deletar/<int:link_id>')
@login_required
@admin_required
def deletar_link(link_id):
    link = Link.query.get_or_404(link_id)
    db.session.delete(link)
    db.session.commit()
    flash('Link deletado com sucesso.', 'info')
    return redirect(url_for('index'))

@app.route('/editar/<int:link_id>', methods=['GET', 'POST'])
@login_required
def editar_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        novo_codigo = request.form.get('codigo_personalizado')
        nova_data_expiracao_str = request.form.get('data_expiracao')
        link_existente = Link.query.filter(Link.short_code == novo_codigo, Link.id != link_id).first()
        if link_existente:
            flash(f'O código "{novo_codigo}" já está em uso por outro link. Tente um diferente.', 'danger')
            return redirect(url_for('editar_link', link_id=link.id))
        link.short_code = novo_codigo
        if nova_data_expiracao_str:
            try:
                # Lógica de conversão de fuso horário correta
                naive_datetime = datetime.strptime(nova_data_expiracao_str, '%Y-%m-%dT%H:%M')
                brt_datetime = BR_TIMEZONE.localize(naive_datetime)
                link.expires_at = brt_datetime.astimezone(pytz.utc)
            except ValueError:
                flash('Formato de data e hora inválido.', 'danger')
                return redirect(url_for('editar_link', link_id=link.id))
        else:
            link.expires_at = None
        db.session.commit()
        flash('Link atualizado com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('editar_link.html', link=link)

# --- (O RESTO DO ARQUIVO, com detalhes, export, qrcode, admin, etc., permanece o mesmo) ---
# ROTA PARA MOSTRAR OS DETALHES DE UM LINK
@app.route('/detalhes/<int:link_id>')
@login_required
def detalhes_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    cliques = Click.query.filter_by(link_id=link.id).order_by(Click.timestamp.desc()).all()
    return render_template('detalhes_link.html', link=link, cliques=cliques)

# --- ROTAS DE EXPORTAÇÃO DE DADOS ---
@app.route('/export/csv/<int:link_id>')
@login_required
def export_csv(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin': return redirect(url_for('index'))
    cliques = Click.query.filter_by(link_id=link.id).order_by(Click.timestamp.asc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Data e Hora (UTC)', 'Endereço IP', 'Navegador (User Agent)'])
    for clique in cliques:
        writer.writerow([clique.timestamp.strftime('%Y-%m-%d %H:%M:%S'), clique.ip_address, clique.user_agent])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=detalhes_link_{link_id}.csv"})

@app.route('/export/pdf/<int:link_id>')
@login_required
def export_pdf(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin': return redirect(url_for('index'))
    cliques = Click.query.filter_by(link_id=link.id).order_by(Click.timestamp.desc()).all()
    html_para_pdf = render_template('detalhes_pdf.html', link=link, cliques=cliques)
    pdf = HTML(string=html_para_pdf).write_pdf()
    return Response(pdf, mimetype='application/pdf', headers={'Content-Disposition': f'attachment;filename=detalhes_link_{link_id}.pdf'})

# --- ROTAS DE QR CODE - REFEITAS E COM NOVAS FUNCIONALIDADES ---
def create_qr_with_logo(data, logo_path=None, version=1, error_correction='H', box_size=10, border=4):
    error_correction_map = {
        'L': qrcode.constants.ERROR_CORRECT_L,
        'M': qrcode.constants.ERROR_CORRECT_M,
        'Q': qrcode.constants.ERROR_CORRECT_Q,
        'H': qrcode.constants.ERROR_CORRECT_H
    }
    qr = qrcode.QRCode(
        version=version,
        error_correction=error_correction_map.get(error_correction.upper(), qrcode.constants.ERROR_CORRECT_H),
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    if logo_path and os.path.exists(logo_path):
        try:
            logo = Image.open(logo_path)
            logo_size_ratio = 0.25 
            logo_w = int(img.size[0] * logo_size_ratio)
            logo_h = int(img.size[1] * logo_size_ratio)
            logo = logo.resize((logo_w, logo_h))
            pos_w = (img.size[0] - logo_w) // 2
            pos_h = (img.size[1] - logo_h) // 2
            img.paste(logo, (pos_w, pos_h))
        except Exception as e:
            print(f"Erro ao aplicar logo: {e}")
    return img

@app.route('/qrcode/generate/<int:link_id>', methods=['POST'])
@login_required
def generate_qrcode(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403
    version = int(request.form.get('version', 1))
    error_correction = request.form.get('error_correction', 'H')
    box_size = int(request.form.get('box_size', 10))
    border = int(request.form.get('border', 4))
    logo_option = request.form.get('logo_option')
    logo_path, temp_logo_path, custom_logo_filename = None, None, None
    if logo_option == 'default':
        logo_path = 'static/images/logo_prefeitura.png'
        if not os.path.exists(logo_path):
             return jsonify({'error': 'Logo padrão não encontrado no servidor.'}), 500
    elif logo_option == 'custom':
        if 'custom_logo' in request.files:
            custom_logo_file = request.files['custom_logo']
            if custom_logo_file.filename != '':
                filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(custom_logo_file.filename)[1])
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                temp_logo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                custom_logo_file.save(temp_logo_path)
                logo_path = temp_logo_path
                custom_logo_filename = filename
    full_short_url = url_for('redirecionar', short_code=link.short_code, _external=True)
    qr_img = create_qr_with_logo(full_short_url, logo_path, version, error_correction, box_size, border)
    buffer = io.BytesIO()
    qr_img.save(buffer, format='PNG')
    buffer.seek(0)
    img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
    data_uri = f"data:image/png;base64,{img_str}"
    return jsonify({'qr_code_data_uri': data_uri, 'logo_used': logo_option, 'custom_logo_filename': custom_logo_filename})

@app.route('/qrcode/export/<string:file_format>/<int:link_id>')
@login_required
def export_qrcode(file_format, link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id and current_user.role != 'admin':
        return redirect(url_for('index'))
    version = int(request.args.get('version', 1))
    error_correction = request.args.get('error_correction', 'H')
    box_size = int(request.args.get('box_size', 10))
    border = int(request.args.get('border', 4))
    logo_option = request.args.get('logo', 'none')
    custom_logo_filename = request.args.get('custom_logo')
    logo_path, temp_logo_path_to_delete = None, None
    if logo_option == 'default':
        logo_path = 'static/images/logo_prefeitura.png'
    elif logo_option == 'custom' and custom_logo_filename:
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(custom_logo_filename))
        if os.path.exists(temp_path):
            logo_path = temp_path
            temp_logo_path_to_delete = temp_path
    full_short_url = url_for('redirecionar', short_code=link.short_code, _external=True)
    buffer = io.BytesIO()
    mimetype, filename = '', f"qrcode_{link.short_code}.{file_format}"
    if file_format == 'svg':
        qr = qrcode.QRCode(version=version, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=box_size, border=border)
        qr.add_data(full_short_url)
        qr.make(fit=True)
        svg_img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage, fill_color="black")
        svg_img.save(buffer)
        mimetype = 'image/svg+xml'
    else:
        qr_img = create_qr_with_logo(full_short_url, logo_path, version, error_correction, box_size, border)
        if file_format == 'png':
            mimetype = 'image/png'; qr_img.save(buffer, format='PNG')
        elif file_format == 'jpeg':
            mimetype = 'image/jpeg'; qr_img.save(buffer, format='JPEG')
        elif file_format == 'pdf':
            mimetype = 'application/pdf'
            qr_img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
            data_uri = f"data:image/png;base64,{img_str}"
            html_para_pdf = render_template('qrcode_pdf.html', qr_code_data_uri=data_uri)
            pdf_bytes = HTML(string=html_para_pdf).write_pdf()
            buffer = io.BytesIO(pdf_bytes)
        else: return "Formato de arquivo inválido", 400
    if temp_logo_path_to_delete and os.path.exists(temp_logo_path_to_delete):
        os.remove(temp_logo_path_to_delete)
    buffer.seek(0)
    return Response(buffer, mimetype=mimetype, headers={"Content-Disposition": f"attachment;filename={filename}"})


# --- ROTAS DE ADMINISTRAÇÃO ---
@app.route('/admin/usuarios')
@login_required
@admin_required
def admin_usuarios():
    users = User.query.all()
    return render_template('admin_usuarios.html', users=users)

@app.route('/admin/usuario/criar', methods=['POST'])
@login_required
@admin_required
def admin_criar_usuario():
    username = request.form.get('username')
    role = request.form.get('role')
    if not username or not role:
        flash('Nome de usuário e tipo são obrigatórios.', 'danger')
        return redirect(url_for('admin_usuarios'))
    if User.query.filter_by(username=username).first():
        flash('Este nome de usuário já existe.', 'warning')
        return redirect(url_for('admin_usuarios'))
    new_user = User(username=username, role=role, precisa_resetar_senha=True)
    new_user.set_password('1234')
    db.session.add(new_user)
    db.session.commit()
    flash(f'Usuário "{username}" criado com sucesso! A senha inicial é "1234".', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/resetar-senha/<int:user_id>')
@login_required
@admin_required
def admin_resetar_senha(user_id):
    user_to_reset = User.query.get_or_404(user_id)
    if user_to_reset.id == current_user.id:
        flash('Você não pode forçar a redefinição da sua própria senha.', 'warning')
        return redirect(url_for('admin_usuarios'))
    user_to_reset.precisa_resetar_senha = True
    user_to_reset.set_password('1234')
    db.session.commit()
    flash(f'Redefinição de senha forçada para "{user_to_reset.username}". A nova senha temporária é "1234".', 'info')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/deletar/<int:user_id>')
@login_required
@admin_required
def deletar_usuario(user_id):
    if user_id == current_user.id:
        flash('Você não pode deletar sua própria conta de administrador.', 'danger')
        return redirect(url_for('admin_usuarios'))
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'Usuário "{user_to_delete.username}" deletado com sucesso.', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/promover/<int:user_id>')
@login_required
@admin_required
def promover_usuario(user_id):
    if user_id == current_user.id:
        flash('Ação não permitida. Você não pode alterar seu próprio papel.', 'danger')
        return redirect(url_for('admin_usuarios'))
    user_to_toggle = User.query.get_or_404(user_id)
    if user_to_toggle.role == 'admin':
        user_to_toggle.role = 'básico'
        flash(f'O usuário "{user_to_toggle.username}" foi rebaixado para básico.', 'info')
    else:
        user_to_toggle.role = 'admin'
        flash(f'O usuário "{user_to_toggle.username}" foi promovido para administrador!', 'success')
    db.session.commit()
    return redirect(url_for('admin_usuarios'))

# COMANDOS DE LINHA DE COMANDO
@app.cli.command("init-db")
def init_db_command():
    """Cria todas as tabelas do banco de dados."""
    db.create_all()
    print("Banco de dados inicializado e tabelas criadas.")

@app.cli.command("criar-admin")
@click.argument("username")
@click.argument("password")
def criar_admin(username, password):
    """Cria o primeiro usuário administrador do sistema."""
    if User.query.first() is not None:
        print("Erro: Já existem usuários no banco de dados. Este comando só pode ser usado com o banco de dados vazio.")
        return
    if User.query.filter_by(username=username).first():
        print(f"Erro: O usuário '{username}' já existe.")
        return
    admin_user = User(username=username, role='admin', precisa_resetar_senha=False)
    admin_user.set_password(password)
    db.session.add(admin_user)
    db.session.commit()
    print(f"Administrador '{username}' criado com sucesso!")


# --- INICIALIZAÇÃO DO SERVIDOR ---
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all()
    app.run(debug=True)