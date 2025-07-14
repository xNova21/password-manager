import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
import random
import string
import os
import bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'bgAAAAABmz0GodfLRcomHAqsHUfy3p4GuLxY24i5rPjJ2A8xZMNP2e724a8XVSnC_G_5jhWbZnCHEoq5p7uRLeg1Cy3e65NQDVw=='  # Cambia esto a una clave segura

DATABASE = 'passwords.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE,
                            hashed_password BLOB,
                            encryption_key BLOB);''')
        conn.execute('''CREATE TABLE IF NOT EXISTS credentials (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER,
                            service TEXT,
                            username TEXT,
                            password TEXT,
                            FOREIGN KEY (user_id) REFERENCES users (id));''')


init_db()

# Function to generate a new encryption key
def generate_encryption_key():
    return Fernet.generate_key()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Function to check hashed password
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Function to encrypt data using the user's encryption key
def encrypt_data(encryption_key, data):
    fernet = Fernet(encryption_key)
    return fernet.encrypt(data.encode())

# Function to decrypt data using the user's encryption key
def decrypt_data(encryption_key, data):
    fernet = Fernet(encryption_key)
    return fernet.decrypt(data).decode()

def generate_password(length, include_uppercase=True, include_lowercase=True, include_numbers=True, include_symbols=True):
    characters = ''
    categories = []
    if include_uppercase:
        characters += string.ascii_uppercase
        categories.append(string.ascii_uppercase)
    if include_lowercase:
        characters += string.ascii_lowercase
        categories.append(string.ascii_lowercase)
    if include_numbers:
        characters += string.digits
        categories.append(string.digits)
    if include_symbols:
        characters += string.punctuation
        categories.append(string.punctuation)
    
    if not characters:
        raise ValueError("You must choose at least one type of character.")

    if length < len(categories):
        raise ValueError(f"The length must be at least {len(categories)} to include each selected character type.")
    
    # Asegurar que al menos un carácter de cada categoría esté presente
    password = [random.choice(categoria) for categoria in categories]
    
    # Completar el resto de la password
    password += [random.choice(characters) for _ in range(length - len(categories))]
    
    # Mezclar los characters
    random.shuffle(password)
    
    return ''.join(password)


@app.route('/', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_password = request.form['password']
        if not username or not user_password:
            flash('Please enter both username and password', 'error')
            return redirect(url_for('login'))
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute("SELECT id, hashed_password, encryption_key FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and check_password(user[1], user_password):
                session['user_id'] = user[0]
                session['encryption_key'] = user[2]
                flash('You were successfully logged in', 'success')
                return redirect(url_for('list_passwords'))
            else:
              flash('Login Unsuccessful. Please check username and password', 'error')    

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        user_password = request.form['password']
        if not username or not user_password:
            flash('Please enter both username and password', 'error')
            return redirect(url_for('register'))
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute("SELECT id, hashed_password, encryption_key FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
            else:
                encryption_key = generate_encryption_key()
                hashed_password = hash_password(user_password)
                conn.execute("INSERT INTO users (username, hashed_password, encryption_key) VALUES (?, ?, ?)", (username, hashed_password, encryption_key))
                conn.commit()
                session['user_id'] = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
                session['encryption_key'] = encryption_key
                flash('User registered successfully!', 'success')
                return redirect(url_for('list_passwords'))
    return render_template('register.html')

@app.route('/generate_new', methods=['GET', 'POST'])
def generate_new():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = session['user_id']
        encryption_key = session['encryption_key']
        length = request.form.get('length', type=int)
        include_uppercase = 'uppercase' in request.form
        include_lowercase = 'lowercase' in request.form
        include_numbers = 'numbers' in request.form
        include_symbols = 'symbols' in request.form
       

        
        if not length or length <= 0:
            flash("Please enter a valid length.", "error")
            return redirect(url_for('generate_new'))
       
        if not (include_uppercase or include_lowercase or include_numbers or include_symbols):
            flash("You must choose at least one type of character.", "error")
            return redirect(url_for('generate_new'))
        
        # Generar la password
        try:
            password = generate_password(
                length,
                include_uppercase,
                include_lowercase,
                include_numbers,
                include_symbols
            )
        except ValueError as ve:
            flash(str(ve), "error")
            return redirect(url_for('generate_new'))
        
        username = encrypt_data(encryption_key, request.form['username'])
        service = request.form['url']
        print(password)
        encrypted_password = encrypt_data(encryption_key, password)
        # Guardar en la base de datos
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('''
                INSERT INTO credentials (user_id, service, username, password) VALUES (?, ?, ?, ?)
            ''', (user_id, service, username, encrypted_password))
            conn.commit()
            conn.close()
        except Exception as e:
            flash("Error al guardar la password en la base de datos.", "error")
            return redirect(url_for('generate_new'))
        
        # Mostrar la password generada
        return render_template('result.html', password=password)
    
    return render_template('generate_new.html')

@app.route('/list', methods=['GET', 'POST']) 
def list_passwords():
    print(request.method)
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'GET':
     user_id = session['user_id']
     encryption_key = session['encryption_key']
     try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.execute("SELECT id, service, username, password FROM credentials WHERE user_id = ?", (user_id,))
        data = []
        for row in cursor.fetchall():
            decrypted_username = decrypt_data(encryption_key, row[2])
            decrypted_password = decrypt_data(encryption_key, row[3])
            print (decrypted_password)
            symbols = ["'", '"', '`', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', '\\', ';', ':', ',', '.', '<', '>', '/', '?']
            for symbol in symbols:
                if symbol != '\\':
                    decrypted_password = decrypted_password.replace(symbol, '\\' + symbol)
                    decrypted_username = decrypted_username.replace(symbol, '\\' + symbol)


            data.append({'id':row[0], 'service': row[1], 'username': decrypted_username, 'password': decrypted_password})

        conn.close()
        return render_template('list.html', data=data)
     except Exception as e:
        flash("Error getting passwords list.", "error")
        return redirect(url_for('generate_new'))
    
    if request.method == 'POST':
        user_id = session['user_id']
        id = request.form['id']

        try:
            conn = sqlite3.connect(DATABASE)
            conn.execute("DELETE FROM credentials WHERE user_id = ? AND id = ?", (user_id, id))
            conn.commit()
            conn.close()
            flash("Password deleted successfully.", "success")
            return redirect(url_for('list_passwords'))
        except Exception as e:
            flash("Error deleting password.", "error")
            return redirect(url_for('list_passwords'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('encryption_key', None)
    flash('You were successfully logged out', 'success')
    return redirect(url_for('login'))

@app.route('/add_new', methods=['GET', 'POST'])
def add_new():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = session['user_id']
        encryption_key = session['encryption_key']
        username = encrypt_data(encryption_key, request.form['username'])
        service = request.form['url']
        password = encrypt_data(encryption_key, request.form['password'])
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('''
                INSERT INTO credentials (user_id, service, username, password) VALUES (?, ?, ?, ?)
            ''', (user_id, service, username, password))
            conn.commit()
            conn.close()
            flash("Password saved successfully.", "success")
            return redirect(url_for('list_passwords'))
        except Exception as e:
            flash("Error saving password.", "error")
            return redirect(url_for('add_new'))
    return render_template('add_new.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_password(id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if request.method == 'GET':
            user_id = session['user_id']
            encryption_key = session['encryption_key']
            try:
                conn = sqlite3.connect(DATABASE)
                cursor = conn.execute("SELECT id, service, username, password FROM credentials WHERE user_id = ? AND id = ?", (user_id, id))
                row = cursor.fetchone()
                if row:
                    decrypted_username = decrypt_data(encryption_key, row[2])
                    decrypted_password = decrypt_data(encryption_key, row[3])
                    symbols = ["'", '"', '`', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', '\\', ';', ':', ',', '.', '<', '>', '/', '?']
                    for symbol in symbols:
                        if symbol != '\\':
                            decrypted_password = decrypted_password.replace(symbol, '\\' + symbol)
                            decrypted_username = decrypted_username.replace(symbol, '\\' + symbol)
                    data = {'id': row[0], 'service': row[1], 'username': decrypted_username, 'password': decrypted_password}
                    conn.close()
                    return render_template('edit.html', data=data)
                else:
                    flash("Password not found.", "error")
                    return redirect(url_for('list_passwords'))
            except Exception as e:
                flash("Error getting password details.", "error")
                return redirect(url_for('list_passwords'))
        
        if request.method == 'POST':
            user_id = session['user_id']
            encryption_key = session['encryption_key']
            username = encrypt_data(encryption_key, request.form['username'])
            service = request.form['url']
            password = encrypt_data(encryption_key, request.form['password'])
            try:
                conn = sqlite3.connect(DATABASE)
                conn.execute("UPDATE credentials SET service = ?, username = ?, password = ? WHERE user_id = ? AND id = ?", (service, username, password, user_id, id))
                conn.commit()
                conn.close()
                flash("Password updated successfully.", "success")
                return redirect(url_for('list_passwords'))
            except Exception as e:
                flash("Error updating password.", "error")
                return redirect(url_for('edit_password', id=id))

if __name__ == "__main__":
    app.run(debug=True)