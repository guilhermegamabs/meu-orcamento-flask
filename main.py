from flask import Flask, redirect, url_for, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

# Banco de Dados
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from .config import Config
from . import models

# UserMixin - implementações padrão métodos de autenticação
class User(UserMixin):
    def __init__(self, id, email, nome, senha):
        self.id = id
        self.email = email
        self.nome = nome
        self.senha = senha
        
# FORMULÁRIO DE LOGIN
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

USERS_DB = {
    "1": User(id="1", email="joao@example.com", nome="João Silva",senha='1234'),
    "2": User(id="2", email="maria@example.com", nome="Maria Santos", senha='321')
}

db = SQLAlchemy()
migrate = Migrate()
   
app = Flask(__name__)
app.secret_key = 'pitoco'
app.config.from_object(Config)

db.init_app(app)
migrate.init_app(app, db)



login_manager = LoginManager()
login_manager.init_app(app)
# Caso não esteja logado, vai ser redirecionado para 'login'
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça o login para acessar esta página."


@login_manager.user_loader
def load_user(user_id):
    return USERS_DB.get(user_id)

# TEST
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    return 'Você não está logado. <a href="/login">Entrar</a>'

@app.route('/login', methods=['GET', 'POST'])
@login_required
def login():
    # Se o usuário já estiver logado, redireciona para a página inicial
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    # Isso só será verdade quando o formulário for enviado (POST) e passar nas validações
    if form.validate_on_submit():
        # Busca o usuário pelo email no nosso "banco de dados"
        user = next((user for user in USERS_DB.values() if user.email == form.email.data), None)
        
        # Verifica se o usuário existe e se a senha está correta
        if user and user.password == form.password.data:
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email ou senha inválidos. Tente novamente.', 'danger')
            
    # Se a requisição for GET ou a validação falhar, renderiza o template do formulário
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)