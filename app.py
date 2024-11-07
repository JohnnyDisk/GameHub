import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import pyotp
import qrcode
import sqlite3
import hashlib

app = Flask(__name__)

app.secret_key = "test"

if not os.path.exists('static/qrcode'):
    os.makedirs('static/qrcode')

def init_db():
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    
    # Create table for storing QR codes (existing)
    c.execute('''CREATE TABLE IF NOT EXISTS qrcodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qrcode_num INTEGER
        )''')

    # Create table for storing user information
    c.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            totp_key TEXT
        )''')

    # Create table for storing game counters
    c.execute('''CREATE TABLE IF NOT EXISTS spill_counters (
            id INTEGER PRIMARY KEY,
            spill1_count INTEGER DEFAULT 0,
            spill2_count INTEGER DEFAULT 0
        )''')

    # Initialize the QR code table if empty
    c.execute('SELECT * FROM qrcodes')
    if not c.fetchone():
        c.execute('INSERT INTO qrcodes (qrcode_num) VALUES (0)')

    # Initialize the counters table if empty
    c.execute('SELECT * FROM spill_counters')
    if not c.fetchone():
        c.execute('INSERT INTO spill_counters (id, spill1_count, spill2_count) VALUES (1, 0, 0)')
    
    # Alter table to add 'chakra' and 'rebirth' columns if they do not exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN chakra INTEGER DEFAULT 10")
        c.execute("ALTER TABLE users ADD COLUMN rebirth INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        # Columns already exist, proceed without error
        pass

    conn.commit()
    conn.close()

init_db()

def load_game_progress(username):
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    c.execute('SELECT chakra, rebirth FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result if result else (0, 0)

def save_game_progress(username, chakra, rebirth):
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    c.execute('UPDATE users SET chakra = ?, rebirth = ? WHERE username = ?', (chakra, rebirth, username))
    conn.commit()
    conn.close()

@app.route('/save_game', methods=['POST'])
def save_game():
    if 'username' in session:
        data = request.json
        chakra = data.get('chakra', 0)
        rebirth = data.get('rebirth', 0)
        save_game_progress(session['username'], chakra, rebirth)
        return jsonify(status="success")
    return jsonify(status="error"), 403

def get_leaderboard():
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    # Assuming you want to sort by `chakra` and then `rebirth` descending
    c.execute("SELECT username, chakra, rebirth FROM users ORDER BY chakra DESC, rebirth DESC LIMIT 10")
    leaderboard = c.fetchall()
    conn.close()
    return leaderboard


@app.route('/leaderboard')
def leaderboard():
    username = session.get('username')
    leaderboard_data = get_leaderboard()
    return render_template('leaderboard.html', leaderboard=leaderboard_data, username=username)


# Function to get the current counts for spill1 and spill2
def get_spill_counts():
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    
    c.execute('SELECT spill1_count, spill2_count FROM spill_counters WHERE id = 1')
    result = c.fetchone()
    conn.close()

    if result:
        return result[0], result[1]  # spill1_count, spill2_count
    else:
        return 0, 0

# Function to update the spill1 or spill2 count
def update_spill_count(spill1=None, spill2=None):
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()

    if spill1 is not None:
        c.execute('UPDATE spill_counters SET spill1_count = ? WHERE id = 1', (spill1,))
    
    if spill2 is not None:
        c.execute('UPDATE spill_counters SET spill2_count = ? WHERE id = 1', (spill2,))
    
    conn.commit()
    conn.close()

def delete_all_old_qr_codes():
    folder_path = 'static/qrcode'
    for filename in os.listdir(folder_path):
        if filename.endswith('.png'):
            os.remove(os.path.join(folder_path, filename))  # Delete all .png files in the folder

def get_and_increment_qr_num():
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    
    c.execute('SELECT qrcode_num FROM qrcodes WHERE id = 1')
    current_num = c.fetchone()[0]
    
    new_num = current_num + 1
    c.execute('UPDATE qrcodes SET qrcode_num = ? WHERE id = 1', (new_num,))
    
    conn.commit()
    conn.close()
    
    return new_num

def generate_qr_code(username):
    # Delete all existing QR codes
    delete_all_old_qr_codes()

    qrcode_num = get_and_increment_qr_num()
    
    # Get user's TOTP key from the database
    conn = sqlite3.connect('qrcode.db')
    c = conn.cursor()
    c.execute('SELECT totp_key FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user:
        totp_key = user[0]
        uri = pyotp.totp.TOTP(totp_key).provisioning_uri(name=username, issuer_name="testapp")
    
        filename = f"static/qrcode/{qrcode_num}.png"
        qrcode.make(uri).save(filename)
    
        # Store qrcode_num in the session
        session['qrcode_num'] = qrcode_num

        return filename

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    username = session.get('username')
    if not username:
        return 'User is not logged in', 403
    
    return jsonify(message="QR code generated and saved successfully.")

# Home route with user info display
@app.route('/')
def home():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/spill1')
def spill1():
    spill1_count, spill2_count = get_spill_counts()  # Fetch current counts from DB
    spill1_count += 1
    update_spill_count(spill1=spill1_count)  # Update the new count in the DB
    return redirect(url_for('memory_game'))

# Spill 2 counter route
@app.route('/spill2')
def spill2():
    spill1_count, spill2_count = get_spill_counts()  # Fetch current counts from DB
    spill2_count += 1
    update_spill_count(spill2=spill2_count)  # Update the new count in the DB
    return redirect(url_for('naruto_game'))

# Route to get the counts for spill 1 and spill 2
@app.route('/get_counts', methods=['GET'])
def get_counts():
    spill1_count, spill2_count = get_spill_counts()  # Fetch current counts from DB
    return jsonify(spill1_count=spill1_count, spill2_count=spill2_count)

@app.route('/memory_game')
def memory_game():
    username = session.get('username')
    return render_template('memory_game.html', username=username)

@app.route('/naruto_game')
def naruto_game():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Load the user's saved game state
    chakra, rebirth = load_game_progress(session['username'])
    return render_template('naruto_game.html', chakra=chakra, rebirth=rebirth)



## User stuff bellow here ##

import re  # For regular expressions

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Valider brukernavn
        if len(username) < 3:
            flash('Brukernavnet må være minst 3 tegn langt.', 'danger')
            return redirect(url_for('register'))

        # Regex for å sjekke at brukernavnet ikke har mellomrom eller spesialtegn
        if not re.match("^[A-Za-z0-9_-]+$", username):
            flash('Brukernavnet kan kun inneholde bokstaver, tall, understreker (_) og bindestreker (-).', 'danger')
            return redirect(url_for('register'))

        # Valider passordlengde
        if len(password) < 6:
            flash('Passordet må være minst 6 tegn langt.', 'danger')
            return redirect(url_for('register'))

        # Sjekk at passordene samsvarer
        if password != confirm_password:
            flash('Passordene samsvarer ikke.', 'danger')
            return redirect(url_for('register'))

        # Hash passordet for sikkerhet
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Generer en ny TOTP-nøkkel for brukeren
        totp_key = pyotp.random_base32()

        # Lagre brukeren i SQLite-databasen
        conn = sqlite3.connect('qrcode.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password_hash, totp_key) VALUES (?, ?, ?)', 
                      (username, password_hash, totp_key))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash('Brukernavn eksisterer allerede, vennligst velg et annet.', 'danger')
            return redirect(url_for('register'))
        conn.close()

        # Sett brukeren i sesjonen
        session['username'] = username

        # Generer og lagre QR-koden for 2FA
        qr_image_path = generate_qr_code(username)

        return redirect(url_for('show_qrcode', username=username))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        flash(f'Du er allerede logget inn som {session["username"]}.', 'info')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password to compare with the stored hashed password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Fetch user info from the database
        conn = sqlite3.connect('qrcode.db')
        c = conn.cursor()
        c.execute('SELECT password_hash, totp_key FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        # If the user exists and the password is correct
        if user and user[0] == password_hash:
            session['pending_username'] = username
            return redirect(url_for('verify_2fa'))
        else:
            flash("Ugyldige innloggingsopplysninger, prøv igjen.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html', username=session.get('username'))


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_username' not in session:
        return redirect(url_for('login'))

    username = session['pending_username']
    if request.method == 'POST':
        otp = request.form['otp']
        
        # Fetch TOTP key from the database
        conn = sqlite3.connect('qrcode.db')
        c = conn.cursor()
        c.execute('SELECT totp_key FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user:
            totp = pyotp.TOTP(user[0])
            if totp.verify(otp):
                session['username'] = username
                session.pop('pending_username', None)  # Remove temporary storage
                flash("Innlogging vellykket!", "success")
                return redirect(url_for('home'))
            else:
                flash("Ugyldig OTP, prøv igjen.", "danger")

    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    # Clear the session to log out the user
    session.clear()
    flash("Du har blitt logget ut.", "success")
    return redirect(url_for('home'))

@app.route('/show_qrcode/<username>', methods=['GET', 'POST'])
def show_qrcode(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    # Get the qrcode_num from session
    qrcode_num = session.get('qrcode_num')

    if request.method == 'POST':
        otp = request.form['otp']   
        
        # Fetch TOTP key from the database
        conn = sqlite3.connect('qrcode.db')
        c = conn.cursor()
        c.execute('SELECT totp_key FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user:
            totp = pyotp.TOTP(user[0])
            if totp.verify(otp):
                session.pop('pending_username', None)
                flash("Verifisering vellykket!", "success")
                return redirect(url_for('home'))
            else:
                flash("Ugyldig OTP, prøv igjen.", "danger")

    if qrcode_num:
        # Display the QR code for the registered user from 'static/qrcode/'
        qr_image_path = f'/static/qrcode/{qrcode_num}.png'
        return render_template('show_qrcode.html', qr_image_path=qr_image_path)
    else:
        return "QR-kode ikke generert."

# Main entry point for the application
if __name__ == '__main__':
    app.run(debug=True)
