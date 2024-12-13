import os
import pathlib
import requests
import secrets
import bcrypt
from flask_mail import Mail, Message
import mysql.connector as connector
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, make_response
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime
import locale
import time
from flask import jsonify
import random
import mysql.connector
import re
import midtransclient
import pandas as pd
from fpdf import FPDF
import io
from flask_socketio import join_room, leave_room, send, SocketIO
from string import ascii_uppercase

# Flask app setup
app = Flask(__name__)
app.secret_key = 'TakeHome'
socketio = SocketIO(app)

try:
    locale.setlocale(locale.LC_ALL, 'id_ID.UTF-8')
except locale.Error:
    locale.setlocale(locale.LC_ALL, '')

@app.template_filter('format_rupiah')
def format_rupiah(value):
    try:
        return f"Rp {int(value):,}".replace(",", ".")
    except (ValueError, TypeError):
        return value


app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')

db_config = {
    'host': 'bismillahtakehome.mysql.database.azure.com',
    'user': 'bismillahtakehome',
    'password': 'W6ALd+AV[_ogEu9',
    'database': 'ecommerce',
    'port': 3306,

}


db = connector.connect(**db_config)
cursor = db.cursor(dictionary=True)

# Flask Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'takehome6993@gmail.com'
app.config['MAIL_PASSWORD'] = 'wqgv olhl szsd nteu'
app.config['MAIL_DEFAULT_SENDER'] = 'TAKE HOME'
mail = Mail(app)

# Google OAuth2 setup
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "288083806039-dn4v3d7874gls0ltcvacbfrmdl9l4i97.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"

)

def login_is_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        # Periksa apakah pengguna telah login (melalui Google atau manual)
        if "user_id" not in session:
            return abort(401)  # Unauthorized
        return function(*args, **kwargs)
    return wrapper


UPLOAD_FOLDER = 'static/profile_pics'  # Folder tempat menyimpan foto
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Ekstensi file yang diperbolehkan

# Fungsi untuk memeriksa ekstensi file yang valid
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = 'static/uploads/profile_pics'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.template_filter('rupiah')
def rupiah(value):
    try:
        return 'Rp {:,.2f}'.format(value)
    except (ValueError, TypeError):
        return value

# Konfigurasi Midtrans
MIDTRANS_SERVER_KEY = 'SB-Mid-server-lIGAMq61azdQQ8fP5nz38zWS'
MIDTRANS_CLIENT_KEY = 'SB-Mid-client-pNHI-sG8bPdq2_9l'

snap = midtransclient.Snap(
    is_production=False,  # Gunakan sandbox untuk pengujian
    server_key=MIDTRANS_SERVER_KEY
)

rooms = {}

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

@app.template_filter('date')
def format_date(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value

@app.route('/')
def index():
    cursor = db.cursor()
    # Ambil kategori yang dipilih dari parameter GET
    kategori_filter = request.args.getlist('kategori', type=int)

    if kategori_filter:
        format_strings = ','.join(['%s'] * len(kategori_filter))
        query = f'''
            SELECT d.*, k.nama_kategori 
            FROM dashboard d
            JOIN kategori k ON d.kategori_id = k.id
            WHERE k.id IN ({format_strings})
        '''
        cursor.execute(query, tuple(kategori_filter))
    else:
        query = '''
            SELECT d.*, k.nama_kategori 
            FROM dashboard d
            JOIN kategori k ON d.kategori_id = k.id
        '''
        cursor.execute(query)

    # Ambil barang
    columns = [desc[0] for desc in cursor.description]
    barang = [dict(zip(columns, row)) for row in cursor.fetchall()]

    # Ambil semua kategori
    cursor.execute('SELECT * FROM kategori')
    kategori = [dict(id=row[0], nama_kategori=row[1]) for row in cursor.fetchall()]

    cursor.close()

    # Kirim kategori_filter untuk digunakan di template
    return render_template('index.html', barang=barang, kategori=kategori, kategori_filter=kategori_filter)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
        role = "Pembeli"

        # Cek apakah file gambar ada di form
        profile_pic = None
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                # Membuat nama file yang aman
                filename = secure_filename(file.filename)
                # Pastikan nama file unik
                filename = str(int(time.time())) + '_' + filename
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                profile_pic = filename  # Menyimpan nama file gambar

        # Mendapatkan ID role
        cursor.execute("SELECT id FROM roles WHERE role_name = %s LIMIT 1", (role,))
        role_data = cursor.fetchone()

        if role_data:
            role_id = role_data['id']
        else:
            flash('Role not found!', 'danger')
            return redirect(url_for('register'))

        # Menyimpan data pengguna di database
        cursor.execute("INSERT INTO users (username, email, password, role_id, profile_pic) VALUES (%s, %s, %s, %s, %s)",
                       (username, email, password, role_id, profile_pic))
        db.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['role'] = user['role_id']
            flash('Login successful!', 'success')

            if user['role_id'] == 1:  # Pembeli
                return redirect(url_for('dashboard_buyer'))
            else:  # Penjual
                return redirect(url_for('dashboard_seller'))

        flash('Invalid email or password!', 'danger')
    return render_template('login.html')


@app.route('/login/google')
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = google.auth.transport.requests.Request(session=request_session)
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=cached_session,
        audience=GOOGLE_CLIENT_ID
    )

    email = id_info.get("email")

    # Cek email di database
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        # Simpan data pengguna ke sesi
        session["user_id"] = user["id"]
        session["name"] = id_info.get("name")
        session["role"] = user["role_id"]
        session["google_id"] = id_info.get("sub")  # Pastikan google_id disimpan
        flash("Google login successful!", "success")

        # Redirect sesuai role
        if user["role_id"] == 1:  # Pembeli
            return redirect(url_for("dashboard_buyer"))
        else:  # Penjual
            return redirect(url_for("dashboard_seller"))
    else:
        # Email tidak terdaftar
        flash("Access denied: Email not registered in the system.", "danger")
        return redirect(url_for("login"))

@app.route('/reset-password/', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        try:
            email = request.form['email']
        except KeyError:
            flash('Email field is missing', 'danger')
            return redirect(url_for('reset_password'))

        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            token = secrets.token_hex(16)
            cursor.execute("INSERT INTO reset_tokens (user_id, token) VALUES (%s, %s)", (user['id'], token))
            db.commit()

            reset_url = url_for('reset_password_token', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            
            msg.html = render_template('isi_email.html', reset_url=reset_url)
            mail.send(msg)

            flash('Password reset email sent!', 'success')
            return redirect(url_for('cek_mail'))
        else:
            flash('Email not found!', 'danger')

    return render_template('reset_password.html')

@app.route('/cek_mail/')
def cek_mail():
    return render_template('cek_email.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    cursor.execute("SELECT * FROM reset_tokens WHERE token = %s", (token,))
    token_data = cursor.fetchone()

    if not token_data:
        flash('Invalid or expired token!', 'danger')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['password_new']
        print("New password received:", new_password)

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        print("Hashed password:", hashed_password)

        # Update the password in the users table
        try:
            print(f"User ID from token data: {token_data['user_id']}")
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, token_data['user_id']))
            db.commit()

            print("Database commit successful.")
            flash('Password updated successfully!', 'success')
            return redirect(url_for('login'))  # Redirect to login page after password is updated
        except Exception as e:
            print(f"Error updating password: {e}")
            db.rollback()  # Rollback if there is an error
            flash('An error occurred while updating the password.', 'danger')

    return render_template('reset_password_form.html', token=token)

@app.route('/dashboard_buyer/')
@login_is_required
def dashboard_buyer():
    cursor = db.cursor()
    user_id = session.get('user_id')

    if user_id:
        cursor.execute("SELECT username, profile_pic, alamat, nomer_hp FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            username = user[0]
            profile_pic = user[1] if user[1] else 'default.jpg'
            alamat = user[2]
            nomer_hp = user[3]

            # Cek apakah data profil belum lengkap
            missing_fields = []
            if not alamat:
                missing_fields.append("alamat")
            if not nomer_hp:
                missing_fields.append("nomer hp")
            if not user[1]:  # profile_pic
                missing_fields.append("foto profil")

            if missing_fields:
                missing_message = "Mohon lengkapi data: " + ", ".join(missing_fields)
                flash(missing_message, 'warning')
        else:
            flash('User not found!', 'danger')
            return redirect(url_for('login'))
    else:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    # Ambil kategori yang dipilih dari parameter GET
    kategori_filter = request.args.getlist('kategori', type=int)

    if kategori_filter:
        format_strings = ','.join(['%s'] * len(kategori_filter))
        query = f'''
            SELECT d.*, k.nama_kategori 
            FROM dashboard d
            JOIN kategori k ON d.kategori_id = k.id
            WHERE k.id IN ({format_strings})
        '''
        cursor.execute(query, tuple(kategori_filter))
    else:
        query = '''
            SELECT d.*, k.nama_kategori 
            FROM dashboard d
            JOIN kategori k ON d.kategori_id = k.id
        '''
        cursor.execute(query)

    # Ambil barang
    columns = [desc[0] for desc in cursor.description]
    barang = [dict(zip(columns, row)) for row in cursor.fetchall()]

    # Hitung total harga (misalnya jumlah dari harga barang)
    total_harga = sum(float(b['harga']) for b in barang)

    # Ambil semua kategori
    cursor.execute('SELECT * FROM kategori')
    kategori = [dict(id=row[0], nama_kategori=row[1]) for row in cursor.fetchall()]

    cursor.close()

    # Kirim kategori_filter, username, profile_pic, dan total_harga ke template
    return render_template(
        'user/dashboard_buyer.html',
        barang=barang,
        kategori=kategori,
        kategori_filter=kategori_filter,
        username=username,
        profile_pic=profile_pic,
        total_harga=total_harga  # Kirimkan total_harga ke template
    )
    
@app.route('/lengkapi_data/', methods=['GET', 'POST'])
@app.route('/lengkapi_data/<int:user_id>/', methods=['GET', 'POST'])
@login_is_required
def lengkapi_data(user_id=None):
    cursor = db.cursor()

    # Jika tidak ada user_id yang diberikan dalam URL, ambil user_id dari session
    if user_id is None:
        user_id = session.get('user_id')

    # Verifikasi jika user_id dalam session cocok dengan user_id dalam URL
    if session.get('user_id') != user_id:
        flash('Akses ditolak, Anda tidak diizinkan untuk mengedit data pengguna lain!', 'danger')
        return redirect(url_for('dashboard_buyer'))  # Redirect ke halaman dashboard atau halaman yang sesuai

    # Cek apakah ada user_id yang valid
    if not user_id:
        flash('User ID tidak ditemukan!', 'danger')
        return redirect(url_for('login'))  # Redirect ke halaman login jika tidak ada user_id

    if request.method == 'POST':
        alamat = request.form.get('alamat')
        nomer_hp = request.form.get('nomer_hp')
        profile_pic = request.files.get('profile_pic')

        # Validasi data
        if not alamat or not nomer_hp:
            flash('Alamat dan nomor HP tidak boleh kosong!', 'danger')
            return redirect(url_for('lengkapi_data', user_id=user_id))

        # Handle upload profile picture
        profile_pic_filename = None
        if profile_pic and profile_pic.filename != '':
            profile_pic_filename = f"user_{user_id}_{profile_pic.filename}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', profile_pic_filename)
            profile_pic.save(upload_path)
        else:
            # Jika tidak ada file gambar, pakai gambar default
            profile_pic_filename = 'profile_pics/default.jpg'

        # Update data ke database
        query = '''
            UPDATE users 
            SET alamat = %s, nomer_hp = %s, profile_pic = %s 
            WHERE id = %s
        '''
        cursor.execute(query, (alamat, nomer_hp, profile_pic_filename, user_id))
        db.commit()
        cursor.close()

        flash('Data berhasil diperbarui!', 'success')
        return redirect(url_for('dashboard_buyer'))

    # Ambil data pengguna untuk ditampilkan di form
    cursor.execute("SELECT alamat, nomer_hp, profile_pic FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    # Data default jika belum diisi
    user_data = {
        'user_id': user_id,  # Menambahkan user_id ke dalam dictionary
        'alamat': user[0] if user[0] else '',
        'nomer_hp': user[1] if user[1] else '',
        'profile_pic': user[2] if user[2] else 'profile_pics/default.jpg'  # Memastikan bahwa jika profile_pic kosong, menggunakan gambar default
    }

    return render_template('user/lengkapi_data.html', user_data=user_data)


@app.route('/setting_user/<int:user_id>/', methods=['GET', 'POST'])
@login_is_required
def setting_user(user_id):
    cursor = db.cursor()

    # Verifikasi jika user_id dalam session cocok dengan user_id dalam URL
    if session.get('user_id') != user_id:
        flash('Akses ditolak, Anda tidak diizinkan untuk mengedit data pengguna lain!', 'danger')
        return redirect(url_for('dashboard_buyer'))  # Redirect ke halaman dashboard atau halaman yang sesuai

    # Cek apakah ada user_id yang valid
    if not user_id:
        flash('User ID tidak ditemukan!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        alamat = request.form.get('alamat')
        nomer_hp = request.form.get('nomer_hp')
        profile_pic = request.files.get('profile_pic')

        # Validasi data
        if not alamat or not nomer_hp:
            flash('Alamat dan nomor HP tidak boleh kosong!', 'danger')
            return redirect(url_for('setting_user', user_id=user_id))

        # Handle upload profile picture
        profile_pic_filename = None
        if profile_pic and profile_pic.filename != '':
            profile_pic_filename = f"user_{user_id}_{profile_pic.filename}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', profile_pic_filename)
            profile_pic.save(upload_path)
        else:
            # Jika tidak ada file gambar, pakai gambar default
            profile_pic_filename = 'profile_pics/default.jpg'

        # Update data ke database
        query = '''
            UPDATE users 
            SET alamat = %s, nomer_hp = %s, profile_pic = %s 
            WHERE id = %s
        '''
        cursor.execute(query, (alamat, nomer_hp, profile_pic_filename, user_id))
        db.commit()
        cursor.close()

        flash('Pengaturan berhasil diperbarui!', 'success')
        return redirect(url_for('dashboard_buyer'))

    # Ambil data pengguna untuk ditampilkan di form
    cursor.execute("SELECT alamat, nomer_hp, profile_pic FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    # Data default jika belum diisi
    user_data = {
        'user_id': user_id,  # Menambahkan user_id ke dalam dictionary
        'alamat': user[0] if user[0] else '',
        'nomer_hp': user[1] if user[1] else '',
        'profile_pic': user[2] if user[2] else 'profile_pics/default.jpg'  # Memastikan bahwa jika profile_pic kosong, menggunakan gambar default
    }

    return render_template('user/setting_user.html', user_data=user_data)

@app.route('/detail_barang/<int:product_id>/')
@login_is_required
def detail_barang(product_id):
    cursor.execute("SELECT * FROM dashboard WHERE product_id = %s", (product_id,))
    barang = cursor.fetchone()  # Get the product details
    
    # Format the price as Indonesian Rupiah
    harga = locale.currency(barang['harga'], grouping=True).replace("Rp", "").strip()  # remove the "Rp" symbol for later use in the template
    return render_template('user/detail_barang.html', barang=barang, harga=harga)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    product_id = data['productId']
    quantity = data['quantity']
    user_id = session.get('user_id', 1)  # Ganti dengan user_id dari session/login

    if quantity <= 0:
        return jsonify({'message': 'Jumlah barang harus lebih dari 0'}), 400

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Cek apakah produk sudah ada di keranjang
        cursor.execute("SELECT jumlah_barang FROM cart WHERE user_id=%s AND product_id=%s", (user_id, product_id))
        result = cursor.fetchone()

        if result:
            # Update jumlah barang
            cursor.execute("UPDATE cart SET jumlah_barang=%s WHERE user_id=%s AND product_id=%s",
                           (result[0] + quantity, user_id, product_id))
        else:
            # Tambah produk baru ke keranjang
            cursor.execute("INSERT INTO cart (user_id, product_id, jumlah_barang) VALUES (%s, %s, %s)",
                           (user_id, product_id, quantity))

        conn.commit()
        return jsonify({'message': 'Berhasil menambahkan ke keranjang'})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'message': 'Gagal menambahkan ke keranjang'}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/cart')
def cart():
    conn = None  
    cursor = None  
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        user_id = session.get('user_id')
        print(f"User ID: {user_id}")  # Debugging: Cek apakah user_id ada di session
        if not user_id:
            return "User tidak ditemukan", 400

        cursor.execute(""" 
        SELECT c.cart_id, d.nama_produk, d.gambar_produk, c.jumlah_barang, d.harga, 
            (c.jumlah_barang * d.harga) as total_harga
        FROM cart c
        JOIN dashboard d ON c.product_id = d.product_id
        WHERE c.user_id = %s
        """, (user_id,))
        cart_items = cursor.fetchall()

        for item in cart_items:
            item['harga'] = f"Rp {item['harga']:,}".replace(",", ".")
            item['total_harga'] = f"Rp {item['total_harga']:,}".replace(",", ".")

        cursor.execute(""" 
            SELECT SUM(c.jumlah_barang * d.harga) AS total_harga
            FROM cart c
            JOIN dashboard d ON c.product_id = d.product_id
            WHERE c.user_id = %s
        """, (user_id,))
        total_harga = cursor.fetchone()['total_harga'] or 0
        total_harga = f"Rp {total_harga:,}".replace(",", ".")
 

        print(f"Total price: {total_harga}")  # Debugging: Cek total harga
        if total_harga == 0:
            return "Total harga tidak valid!", 400  # User feedback if total is 0

        cursor.execute(""" 
            SELECT SUM(c.jumlah_barang) AS total_items
            FROM cart c
            WHERE c.user_id = %s
        """, (user_id,))
        total_items = cursor.fetchone()['total_items'] or 0  

        print(f"Total items in cart: {total_items}")  # Debugging: Cek jumlah barang

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'total_items': total_items,
                'total_harga': total_harga,
                'cart_items': cart_items
            })

        return render_template('user/cart.html', cart_items=cart_items, total_harga=total_harga, total_items=total_items)

    except Exception as e:
        print(f"Error: {e}")  # Debugging: Cek error
        return f"Terjadi kesalahan: {e}", 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/update_cart', methods=['POST'])
def update_cart():
    data = request.get_json()
    cart_id = data.get('cart_id')
    action = data.get('action')
    
    if not cart_id or action not in ['increment', 'decrement']:
        return jsonify({"success": False, "error": "Invalid input"}), 400
    
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Get the current quantity for the cart item
    cursor.execute("SELECT jumlah_barang FROM cart WHERE cart_id = %s", (cart_id,))
    item = cursor.fetchone()
    
    if item:
        new_quantity = item['jumlah_barang'] + 1 if action == 'increment' else item['jumlah_barang'] - 1
        
        # Make sure the quantity doesn't go below 1
        if new_quantity < 1:
            return jsonify({"success": False, "error": "Quantity cannot be less than 1"}), 400
        
        # Update the cart with the new quantity
        cursor.execute("UPDATE cart SET jumlah_barang = %s WHERE cart_id = %s", (new_quantity, cart_id))
        conn.commit()
        
        # Fetch the updated item data
        cursor.execute(""" 
            SELECT c.cart_id, d.nama_produk, d.gambar_produk, c.jumlah_barang, d.harga, 
                (c.jumlah_barang * d.harga) as total_harga
            FROM cart c
            JOIN dashboard d ON c.product_id = d.product_id
            WHERE c.cart_id = %s
        """, (cart_id,))
        updated_item = cursor.fetchone()
        
        if updated_item:
            updated_item['harga'] = f"Rp {updated_item['harga']:,}".replace(",", ".")
            updated_item['total_harga'] = f"Rp {updated_item['total_harga']:,}".replace(",", ".")
        
        return jsonify({"success": True, "new_quantity": updated_item['jumlah_barang']})

    return jsonify({"success": False, "error": "Item not found"}), 404


@app.route('/update_total_harga', methods=['POST'])
def update_total_harga():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "User not found"}), 400

    cursor.execute("""
        SELECT SUM(c.jumlah_barang * d.harga) AS total_harga
        FROM cart c
        JOIN dashboard d ON c.product_id = d.product_id
        WHERE c.user_id = %s
    """, (user_id,))
    result = cursor.fetchone()
    total_harga = result['total_harga'] if result['total_harga'] else 0
    total_harga = f"Rp {total_harga:,}".replace(",", ".")
    
    return jsonify({"total_harga": total_harga})



@app.route('/cart/delete', methods=['POST'])
def delete_cart_item():
    data = request.get_json()
    cart_id = data.get('cart_id')
    
    if not cart_id:
        return jsonify({"success": False, "error": "Cart ID missing"}), 400
    
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("DELETE FROM cart WHERE cart_id = %s", (cart_id,))
    conn.commit()

    return jsonify({"success": True})


@app.route('/cart/delete_all', methods=['POST'])
def delete_all_cart_items():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'User not logged in'}), 401

        cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
        conn.commit()

        return jsonify({'success': True}), 200
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/cart/item_count', methods=['GET'])
def get_cart_item_count():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        user_id = session.get('user_id')
        print(f"User ID: {user_id}")  # Debugging: Cek apakah user_id ada di session
        if not user_id:
            return jsonify({'count': 0})  # Jika user tidak login, jumlah item 0
        
        # Hitung jumlah total item di keranjang
        cursor.execute("""
            SELECT SUM(c.jumlah_barang) AS total_items
            FROM cart c
            WHERE c.user_id = %s
        """, (user_id,))
        total_items = cursor.fetchone()['total_items'] or 0  # Penanganan jika tidak ada data

        print(f"Total items in cart: {total_items}")  # Debugging: Cek jumlah barang
        return jsonify({'count': total_items})
    except Exception as e:
        print(f"Error: {e}")  # Debugging: Cek error saat menghitung item
        return jsonify({'count': 0, 'error': str(e)})
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# Fungsi untuk mengonversi Decimal ke float
def decimal_to_float(decimal_value):
    return float(decimal_value) if decimal_value is not None else 0.0

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    conn = None
    cursor = None
    try:
        # Pastikan ada user_id dalam session
        user_id = session.get('user_id')
        if not user_id:
            return "User tidak ditemukan", 400

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Ambil data pengguna dari database berdasarkan user_id
        cursor.execute("""
            SELECT id, username, email, alamat, nomer_hp, profile_pic
            FROM users
            WHERE id = %s
        """, (user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            return "Data pengguna tidak ditemukan", 400

        # Ambil total harga dari keranjang belanja
        cursor.execute("""
            SELECT SUM(c.jumlah_barang * d.harga) AS total_harga
            FROM cart c
            JOIN dashboard d ON c.product_id = d.product_id
            WHERE c.user_id = %s
        """, (user_id,))
        total_harga = cursor.fetchone()['total_harga'] or 0
        total_harga = float(total_harga)

        # Jika method POST, proses checkout
        if request.method == 'POST':
            # Ambil data dari form
            nama_lengkap = request.form['nama_lengkap']
            email = request.form['email'].strip()
            alamat = request.form['alamat']
            kota = request.form['kota']
            kode_pos = request.form['kode_pos']
            no_telepon = request.form['no_telepon']

            # Validasi email
            if not re.match(r"[^@]+@[^@]+\.[a-zA-Z]{2,}", email):
                return "Format email tidak valid", 400

            # Simpan data checkout ke tabel orders
            cursor.execute("""
                INSERT INTO orders (user_id, nama_lengkap, alamat, kota, kode_pos, no_telepon, total_harga)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, nama_lengkap, alamat, kota, kode_pos, no_telepon, total_harga))
            conn.commit()

            # Gunakan timestamp untuk membuat order_id yang unik
            timestamp = str(int(time.time()))  # Gunakan timestamp saat ini
            unique_order_id = f"order-{user_id}-{timestamp}"  # Kombinasikan dengan user_id dan timestamp

            # Param untuk transaksi dengan payment_type QRIS
            param = {
                "transaction_details": {
                    "order_id": unique_order_id,
                    "gross_amount": total_harga
                },
                "payment_type": "qris",  # Tentukan metode pembayaran QRIS
                "customer_details": {
                    "first_name": nama_lengkap,
                    "last_name": "",
                    "email": email,
                    "phone": no_telepon
                }
            }

            # Kirim request untuk membuat transaksi
            transaction = snap.create_transaction(param)
            transaction_token = transaction['token']

            return render_template('user/payment.html', transaction_token=transaction_token)

        # Render halaman checkout
        return render_template('user/checkout.html', user_data=user_data, total_harga=total_harga)

    except Exception as e:
        print(f"Error: {e}")
        return f"Terjadi kesalahan: {e}", 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
@app.route('/order_success')
def order_success():
    return render_template('user/order_success.html')


@app.route('/register_user/')
@login_is_required
def register_user():
    # Ambil user_id dari session
    user_id = session.get('user_id')

    if user_id:
        cursor = db.cursor()
        cursor.execute("SELECT username, profile_pic FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            # Tetapkan default jika profile_pic kosong
            profile_pic = user[1] if user[1] else 'default.jpg'
            username = user[0]
        else:
            flash('User not found!', 'danger')
            return redirect(url_for('login'))
    else:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    # Render template dengan variabel
    return render_template(
        'user/setting.html',
        username=username,
        profile_pic=profile_pic
    )

@app.route('/histori/')
@login_is_required
def histori():
    user_id = session.get('user_id')  # Mengambil user_id dari sesi
    if not user_id:
        return redirect('/login')  # Redirect ke login jika user_id tidak ada

    cursor.execute("""
        SELECT 
            payment.payment_id, 
            payment.alamat AS payment_alamat, 
            payment.total, 
            payment.order_number, 
            payment.jumlah, 
            payment.created_at, 
            users.username, 
            users.email 
        FROM 
            payment 
        INNER JOIN 
            users 
        ON 
            payment.user_id = users.id
        WHERE 
            payment.user_id = %s
        ORDER BY 
            payment.created_at DESC
    """, (user_id,))
    transaksi = cursor.fetchall()
    return render_template('user/histori.html', transaksi=transaksi)


@app.route('/dashboard_seller/')
@login_is_required
def dashboard_seller():
    user_id = session.get('user_id')

    if user_id:
        cursor.execute("SELECT username, profile_pic FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user:
            profile_pic = user['profile_pic'] if user['profile_pic'] else 'default.jpg'

            # Fetch barang (products)
            cursor.execute("SELECT nama_produk, harga, gambar_produk FROM dashboard")
            barang = cursor.fetchall()

            # Fetch kategori (categories)
            cursor.execute("SELECT nama_kategori FROM kategori")
            kategori = cursor.fetchall()

            cursor.execute("SELECT payment.payment_id, payment.alamat AS payment_alamat,  payment.total, payment.order_number, payment.jumlah, payment.created_at, users.username, users.email FROM payment INNER JOIN users ON payment.user_id = users.id ORDER BY payment.created_at DESC ")
            transaksi = cursor.fetchall()
            return render_template('admin/dashboard.html', 
                                   username=user['username'], 
                                   profile_pic=profile_pic,
                                   barang=barang,
                                   kategori=kategori,
                                   transaksi=transaksi)
    
    flash('User not found or not logged in!', 'danger')
    return redirect(url_for('login'))


@app.context_processor
def inject_profile_pic():
    user_id = session.get('user_id')
    if user_id:
        cursor.execute("SELECT profile_pic FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user and user['profile_pic']:
            return {'profile_pic': user['profile_pic']}
    return {'profile_pic': 'default.jpg'}

@app.context_processor
def inject_user_data():
    user_id = session.get('user_id')
    if user_id:
        cursor.execute("SELECT profile_pic, username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
            profile_pic = user.get('profile_pic', 'default.jpg')
            username = user.get('username', 'Guest')
            return {'profile_pic': profile_pic, 'username': username}
    return {'profile_pic': 'default.jpg', 'username': 'Guest'}


@app.route('/dashboard_barang/')
@login_is_required
def dashboard_barang():
    cursor.execute("""
        SELECT d.product_id, d.gambar_produk, d.nama_produk, d.harga, d.teks_deskripsi, 
               d.kategori_id, k.nama_kategori, d.stok
        FROM dashboard d
        LEFT JOIN kategori k ON d.kategori_id = k.id
    """)
    barang = cursor.fetchall()
    return render_template('admin/barang.html', barang=barang)


@app.route('/tambah_barang/', methods=['GET', 'POST'])
@login_is_required
def tambah_barang():
    if request.method == 'POST':
        # Ambil data dari form
        nama_produk = request.form['nama_produk']
        deskripsi = request.form['deskripsi']
        harga = request.form['harga']
        kategori_id = request.form['kategori_id']
        stok = request.form['stok']

        # Cek file upload
        if 'gambar_produk' not in request.files or request.files['gambar_produk'].filename == '':
            flash('Gambar produk wajib diunggah.', 'danger')
            return redirect(url_for('tambah_barang'))

        file = request.files['gambar_produk']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
        else:
            flash('Format file tidak valid. Hanya PNG, JPG, dan JPEG diperbolehkan.', 'danger')
            return redirect(url_for('tambah_barang'))

        # Simpan data produk ke database
        cursor.execute(
            "INSERT INTO dashboard (nama_produk, teks_deskripsi, harga, kategori_id, stok, gambar_produk) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (nama_produk, deskripsi, harga, kategori_id, stok, filename)
        )
        db.commit()
        flash('Produk berhasil ditambahkan!', 'success')
        return redirect(url_for('dashboard_barang'))

    # Ambil data kategori untuk dropdown
    cursor.execute("SELECT id, nama_kategori FROM kategori")
    kategori = cursor.fetchall()

    # Tampilkan halaman tambah barang
    return render_template('admin/tambah_barang.html', kategori=kategori)

@app.route('/edit_barang/<int:product_id>/', methods=['GET', 'POST'])
@login_is_required
def edit_barang(product_id):
    # Ambil data barang berdasarkan product_id
    cursor.execute("SELECT * FROM dashboard WHERE product_id = %s", (product_id,))
    barang = cursor.fetchone()

    if not barang:
        flash("Barang tidak ditemukan!", "danger")
        return redirect(url_for('dashboard_barang'))

    # Jika request adalah POST, proses data form untuk update
    if request.method == 'POST':
        nama_produk = request.form.get('nama_produk')
        teks_deskripsi = request.form.get('teks_deskripsi')  # Ganti dari 'deskripsi'
        harga = request.form.get('harga')
        kategori_id = request.form.get('kategori_id')
        stok = request.form.get('stok')

        if nama_produk and teks_deskripsi and harga and kategori_id and stok:
            cursor.execute("""
                UPDATE dashboard SET 
                nama_produk = %s, teks_deskripsi = %s, harga = %s, kategori_id = %s, stok = %s
                WHERE product_id = %s
            """, (nama_produk, teks_deskripsi, harga, kategori_id, stok, product_id))
            db.commit()
            flash("Barang berhasil diperbarui!", "success")
            return redirect(url_for('dashboard_barang'))
        else:
            flash("Semua data harus diisi!", "danger")

    # Ambil data kategori untuk dropdown
    cursor.execute("SELECT * FROM kategori")
    kategori = cursor.fetchall()

    return render_template('admin/edit_barang.html', barang=barang, kategori=kategori)


@app.route('/hapus_barang/<int:barang_id>', methods=['POST'])
@login_is_required
def hapus_barang(barang_id):
    cursor.execute("DELETE FROM barang WHERE id = %s", (barang_id,))
    db.commit()
    flash("Barang berhasil dihapus!", "success")
    return redirect(url_for('dashboard_barang'))

@app.route('/dashboard_kategori/')
@login_is_required
def dashboard_kategori():
    cursor.execute("SELECT * FROM kategori")
    kategori = cursor.fetchall()
    return render_template('admin/kategori_barang.html', kategori=kategori)

@app.route('/tambah_kategori/', methods=['POST'])
@login_is_required
def tambah_kategori():
    kategori = request.form.get('kategori')  # Menggunakan .get() untuk lebih aman
    if kategori:
        cursor = db.cursor()
        cursor.execute("INSERT INTO kategori (nama_kategori) VALUES (%s)", (kategori,))
        db.commit()
        return redirect(url_for('dashboard_kategori'))
    else:
        # Jika kategori kosong
        flash("Kategori tidak boleh kosong!", "danger")
        return redirect(url_for('dashboard_kategori'))

@app.route('/edit_kategori/<int:kategori_id>/', methods=['GET', 'POST'])
@login_is_required
def edit_kategori(kategori_id):
    # Get the category to be edited
    cursor.execute("SELECT * FROM kategori WHERE id = %s", (kategori_id,))
    kategori = cursor.fetchone()

    if not kategori:
        flash("Kategori tidak ditemukan!", "danger")
        return redirect(url_for('dashboard_barang'))

    if request.method == 'POST':
        # Update the category name
        kategori_baru = request.form.get('kategori')
        if kategori_baru:
            cursor.execute("UPDATE kategori SET nama_kategori = %s WHERE id = %s", (kategori_baru, kategori_id))
            db.commit()
            flash("Kategori berhasil diperbarui!", "success")
            return redirect(url_for('dashboard_kategori'))
        else:
            flash("Nama kategori tidak boleh kosong!", "danger")

    return render_template('admin/edit_kategori.html', kategori=kategori)


@app.route('/hapus_kategori/<int:kategori_id>', methods=['POST'])
@login_is_required
def hapus_kategori(kategori_id):
    cursor = db.cursor()
    cursor.execute("DELETE FROM kategori WHERE id = %s", (kategori_id,))
    db.commit()
    flash("Kategori berhasil dihapus!", "success")
    return redirect(url_for('dashboard_kategori'))

@app.route('/dashboard_transaksi/')
@login_is_required
def dashboard_transaksi():
    # Query untuk mendapatkan transaksi dengan data pengguna
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            payment.alamat AS payment_alamat, 
            payment.total, 
            payment.order_number, 
            payment.jumlah, 
            payment.created_at, 
            users.username, 
            users.email 
        FROM 
            payment 
        INNER JOIN 
            users 
        ON 
            payment.user_id = users.id
        ORDER BY 
            payment.created_at DESC
    """)
    transaksi = cursor.fetchall()
    return render_template('admin/transaksi.html', transaksi=transaksi)

@app.route('/dashboard_user/')
@login_is_required
def dashboard_user():
    cursor.execute("SELECT * FROM users WHERE role_id = 2")
    users = cursor.fetchall()
    return render_template('admin/user.html', users=users)

@app.route('/tambah_user_admin_page/')
@login_is_required
def tambah_user_admin_page():
    return render_template('admin/tambah_admin.html')


@app.route('/tambah_user_admin/', methods=['GET', 'POST'])
@login_is_required
def tambah_user_admin():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        alamat = request.form['alamat']
        nomer = request.form['nomer']
        password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
        role = "Penjual"

        # Cek file upload
        if 'profile_pic' not in request.files:
            flash('No file part', 'danger')
            return redirect(url_for('tambah_user_admin'))
        
        file = request.files['profile_pic']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('tambah_user_admin'))

        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            # Tambahkan timestamp untuk membuat nama file unik
            timestamp = str(int(time.time()))  # Gunakan timestamp saat ini
            unique_filename = f"{timestamp}_{original_filename}"  # Gabungkan timestamp dengan nama file asli
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
        else:
            flash('Invalid file type. Only PNG, JPG, and JPEG are allowed.', 'danger')
            return redirect(url_for('tambah_user_admin'))

        # Cek role di database
        cursor.execute("SELECT id FROM roles WHERE role_name = %s LIMIT 1", (role,))
        role_data = cursor.fetchone()

        if role_data:
            role_id = role_data['id']
        else:
            flash('Role not found!', 'danger')
            return redirect(url_for('register'))

        # Simpan data user
        cursor.execute(
            "INSERT INTO users (username, email, password, role_id, profile_pic, alamat, nomer_hp) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (username, email, password, role_id, unique_filename, alamat, nomer)
        )

        db.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('dashboard_user'))

    return render_template('admin/user.html')

@app.route('/hapus_user_admin/<int:user_id>', methods=['GET'])
@login_is_required
def hapus_user_admin(user_id):
    # Cari pengguna berdasarkan user_id
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('dashboard_user'))

    # Hapus data yang berelasi
    cursor.execute("DELETE FROM otp_verifications WHERE user_id = %s", (user_id,))

    # Hapus gambar profil dari server jika ada
    if user['profile_pic']:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user['profile_pic']))
        except FileNotFoundError:
            pass  # Gambar tidak ditemukan

    # Hapus data pengguna dari database
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('dashboard_user'))

@app.route('/edit_user_admin/<int:user_id>', methods=['GET', 'POST'])
@login_is_required
def edit_user_admin(user_id):
    # Fetch the user data
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('dashboard_user'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        alamat = request.form['alamat']
        nomer = request.form['nomer']
        role_id = request.form.get('role_id')  # Fetch role_id from form

        # Handle profile picture update
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            # Remove old profile pic if exists
            if user['profile_pic']:
                old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], user['profile_pic'])
                if os.path.exists(old_pic_path):
                    os.remove(old_pic_path)

            # Generate a new filename using a timestamp
            timestamp = int(time.time())
            filename = f"{timestamp}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Update the user object with the new profile pic filename
            user['profile_pic'] = filename  # Ensure profile_pic is updated

        # Update user data in the database
        try:
            cursor.execute("""
                UPDATE users SET username = %s, email = %s, alamat = %s, nomer_hp = %s, profile_pic = %s, role_id = %s
                WHERE id = %s
            """, (username, email, alamat, nomer, user['profile_pic'], role_id, user_id))  # Ensure user['profile_pic'] is used
            db.commit()
            flash('User updated successfully!', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Error updating user: {e}', 'danger')

        return redirect(url_for('dashboard_user'))

    # Render the edit form with current user data
    return render_template('admin/edit_user.html', user=user)


@app.route('/export/csv')
@login_is_required
def export_csv():
    user_id = session.get('user_id')
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        WHERE 
            payment.user_id = %s
        ORDER BY 
            payment.created_at DESC
    """, (user_id,))
    transaksi = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(transaksi, columns=['Payment ID', 'Total', 'Order Number', 'Created At'])

    # Export ke CSV
    response = make_response(df.to_csv(index=False))
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/export/excel')
@login_is_required
def export_excel():
    user_id = session.get('user_id')
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        WHERE 
            payment.user_id = %s
        ORDER BY 
            payment.created_at DESC
    """, (user_id,))
    transaksi = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(transaksi, columns=['Payment ID', 'Total', 'Order Number', 'Created At'])

    # Gunakan BytesIO untuk buffer memori
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Transaksi')

    # Set response dengan file Excel
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response

@app.route('/export/pdf')
@login_is_required
def export_pdf():
    user_id = session.get('user_id')
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        WHERE 
            payment.user_id = %s
        ORDER BY 
            payment.created_at DESC
    """, (user_id,))
    transaksi = cursor.fetchall()

    # Buat PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Histori Transaksi", ln=True, align='C')
    pdf.ln(10)

    # Tambahkan header tabel
    pdf.cell(50, 10, 'Order Number', 1)
    pdf.cell(50, 10, 'Total', 1)
    pdf.cell(50, 10, 'Created At', 1)
    pdf.ln()

    # Tambahkan data
    for t in transaksi:
        pdf.cell(50, 10, str(t['order_number']), 1)
        pdf.cell(50, 10, str(t['total']), 1)
        pdf.cell(50, 10, str(t['created_at']), 1)
        pdf.ln()

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

# Export untuk Dashboard Barang
@app.route('/dashboard_barang/export/csv')
@login_is_required
def export_barang_csv():
    cursor.execute("""
        SELECT 
            d.product_id, 
            d.gambar_produk, 
            d.nama_produk, 
            d.harga, 
            d.teks_deskripsi, 
            k.nama_kategori, 
            d.stok
        FROM 
            dashboard d
        LEFT JOIN 
            kategori k 
        ON 
            d.kategori_id = k.id
    """)
    barang = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(barang, columns=[
        'Product ID', 'Gambar Produk', 'Nama Produk', 'Harga', 
        'Deskripsi', 'Kategori', 'Stok'
    ])

    # Export ke CSV
    response = make_response(df.to_csv(index=False))
    response.headers['Content-Disposition'] = 'attachment; filename=barang.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/dashboard_barang/export/excel')
@login_is_required
def export_barang_excel():
    cursor.execute("""
        SELECT 
            d.product_id, 
            d.gambar_produk, 
            d.nama_produk, 
            d.harga, 
            d.teks_deskripsi, 
            k.nama_kategori, 
            d.stok
        FROM 
            dashboard d
        LEFT JOIN 
            kategori k 
        ON 
            d.kategori_id = k.id
    """)
    barang = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(barang, columns=[
        'Product ID', 'Gambar Produk', 'Nama Produk', 'Harga', 
        'Deskripsi', 'Kategori', 'Stok'
    ])

    # Gunakan BytesIO untuk buffer memori
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Barang')

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=barang.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response

@app.route('/dashboard_barang/export/pdf')
@login_is_required
def export_barang_pdf():
    cursor.execute("""
        SELECT 
            d.product_id, 
            d.nama_produk, 
            d.harga, 
            d.stok, 
            k.nama_kategori
        FROM 
            dashboard d
        LEFT JOIN 
            kategori k 
        ON 
            d.kategori_id = k.id
    """)
    barang = cursor.fetchall()

    # Buat PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Dashboard Barang", ln=True, align='C')
    pdf.ln(10)

    # Tambahkan header tabel
    pdf.cell(30, 10, 'Product ID', 1)
    pdf.cell(50, 10, 'Nama Produk', 1)
    pdf.cell(30, 10, 'Harga', 1)
    pdf.cell(30, 10, 'Stok', 1)
    pdf.cell(50, 10, 'Kategori', 1)
    pdf.ln()

    # Tambahkan data
    for b in barang:
        pdf.cell(30, 10, str(b['product_id']), 1)
        pdf.cell(50, 10, str(b['nama_produk']), 1)
        pdf.cell(30, 10, str(b['harga']), 1)
        pdf.cell(30, 10, str(b['stok']), 1)
        pdf.cell(50, 10, str(b['nama_kategori']), 1)
        pdf.ln()

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Disposition'] = 'attachment; filename=barang.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

# Export untuk Dashboard Transaksi
@app.route('/dashboard_transaksi/export/csv')
@login_is_required
def export_transaksi_csv():
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            users.username, 
            users.email, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        INNER JOIN 
            users 
        ON 
            payment.user_id = users.id
        ORDER BY 
            payment.created_at DESC
    """)
    transaksi = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(transaksi, columns=[
        'Payment ID', 'Username', 'Email', 'Total', 'Order Number', 'Created At'
    ])

    # Export ke CSV
    response = make_response(df.to_csv(index=False))
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/dashboard_transaksi/export/excel')
@login_is_required
def export_transaksi_excel():
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            users.username, 
            users.email, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        INNER JOIN 
            users 
        ON 
            payment.user_id = users.id
        ORDER BY 
            payment.created_at DESC
    """)
    transaksi = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(transaksi, columns=[
        'Payment ID', 'Username', 'Email', 'Total', 'Order Number', 'Created At'
    ])

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Transaksi')

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response

@app.route('/dashboard_transaksi/export/pdf')
@login_is_required
def export_transaksi_pdf():
    cursor.execute("""
        SELECT 
            payment.payment_id, 
            users.username, 
            payment.total, 
            payment.order_number, 
            payment.created_at
        FROM 
            payment
        INNER JOIN 
            users 
        ON 
            payment.user_id = users.id
        ORDER BY 
            payment.created_at DESC
    """)
    transaksi = cursor.fetchall()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Dashboard Transaksi", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(30, 10, 'Payment ID', 1)
    pdf.cell(40, 10, 'Username', 1)
    pdf.cell(30, 10, 'Total', 1)
    pdf.cell(40, 10, 'Order Number', 1)
    pdf.cell(50, 10, 'Created At', 1)
    pdf.ln()

    for t in transaksi:
        pdf.cell(30, 10, str(t['payment_id']), 1)
        pdf.cell(40, 10, str(t['username']), 1)
        pdf.cell(30, 10, str(t['total']), 1)
        pdf.cell(40, 10, str(t['order_number']), 1)
        pdf.cell(50, 10, str(t['created_at']), 1)
        pdf.ln()

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Disposition'] = 'attachment; filename=transaksi.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

@app.route('/dashboard_user/export/csv')
@login_is_required
def export_user_csv():
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE role_id = 2")
    users = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(users, columns=['User ID', 'Username', 'Email', 'Created At'])

    # Export ke CSV
    response = make_response(df.to_csv(index=False))
    response.headers['Content-Disposition'] = 'attachment; filename=users.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/dashboard_user/export/excel')
@login_is_required
def export_user_excel():
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE role_id = 2")
    users = cursor.fetchall()

    # Konversi ke DataFrame
    df = pd.DataFrame(users, columns=['User ID', 'Username', 'Email', 'Created At'])

    # Gunakan BytesIO untuk buffer memori
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Users')

    # Set response dengan file Excel
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=users.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response

@app.route('/dashboard_user/export/pdf')
@login_is_required
def export_user_pdf():
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE role_id = 2")
    users = cursor.fetchall()

    # Buat PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Daftar Users", ln=True, align='C')
    pdf.ln(10)

    # Tambahkan header tabel
    pdf.cell(40, 10, 'User ID', 1)
    pdf.cell(50, 10, 'Username', 1)
    pdf.cell(70, 10, 'Email', 1)
    pdf.cell(30, 10, 'Created At', 1)
    pdf.ln()

    # Tambahkan data
    for user in users:
        pdf.cell(40, 10, str(user['id']), 1)
        pdf.cell(50, 10, user['username'], 1)
        pdf.cell(70, 10, user['email'], 1)
        pdf.cell(30, 10, str(user['created_at']), 1)
        pdf.ln()

    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Disposition'] = 'attachment; filename=users.pdf'
    response.headers['Content-Type'] = 'application/pdf'
    return response

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    print(f"{name} joined room {room}")


@app.route('/dashboard_user/print')
@login_is_required
def print_user():
    cursor.execute("SELECT id, username, email, created_at FROM users WHERE role_id = 2")
    users = cursor.fetchall()
    return render_template('admin/print_user.html', users=users)

@app.route("/chat_user/", methods=["POST", "GET"])
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor.execute("SELECT username, role_id FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    username = user['username']
    role_id = user['role_id']

    if request.method == "POST":
        # Gunakan username sebagai nama room
        room = username

        # Periksa apakah room sudah ada di database
        cursor.execute("SELECT * FROM rooms WHERE room_name = %s", (room,))
        room_data = cursor.fetchone()

        if not room_data:
            cursor.execute("INSERT INTO rooms (room_name, members_count) VALUES (%s, %s)", (room, 0))
            db.commit()

        session["room"] = room
        session["name"] = username
        return redirect(url_for("room"))

    return render_template("user/home.html", name=username, role_id=role_id)


@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None:
        return redirect(url_for("home"))

    cursor.execute("SELECT sender_name, message, created_at FROM messages WHERE room_name = %s ORDER BY created_at ASC", (room,))
    messages = cursor.fetchall()

    return render_template("user/room2.html", code=room, messages=messages)

@socketio.on("message")
def handle_message(data):
    message_data = {
        "name": session.get("name"),  # Ambil nama dari session
        "message": data["data"],      # Pesan dari client
        "created_at": datetime.now().isoformat()  # Timestamp pesan
    }
    send(message_data, to=session.get("room"))  # Kirim pesan ke room tertentu


@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room:
        cursor.execute("UPDATE rooms SET members_count = members_count - 1 WHERE room_name = %s", (room,))
        db.commit()

        send({"name": name, "message": "has left the room"}, to=room)
        print(f"{name} has left the room {room}")

@app.route("/dashboard_chat/", methods=["POST", "GET"])
def dashboard_chat():
    if "user_id" not in session:
        return redirect(url_for("login"))

    cursor.execute("SELECT username, role_id FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    username = user['username']
    role_id = user['role_id']

    # Fetch available room names from the database
    cursor.execute("SELECT room_name FROM rooms")
    rooms = cursor.fetchall()

    if request.method == "POST":
        room_code = request.form.get("code")  # Form field for room code

        if room_code:
            cursor.execute("SELECT * FROM rooms WHERE room_name = %s", (room_code,))
            room_data = cursor.fetchone()

            if room_data:
                # Jika room ditemukan, set session room dan username
                session["room"] = room_code
                session["name"] = username
                return redirect(url_for("room_admin"))
            else:
                return render_template("admin/home.html", name=username, role_id=role_id, error="Room not found", rooms=rooms)

    return render_template("admin/home.html", name=username, role_id=role_id, rooms=rooms)

@app.route("/room_admin")
def room_admin():
    room = session.get("room")
    name = session.get("name")
    if room is None or name is None:
        return redirect(url_for("home"))

    print(f"User {name} joined room {room}")  # Debugging line

    cursor.execute("SELECT sender_name, message, created_at FROM messages WHERE room_name = %s ORDER BY created_at ASC", (room,))
    messages = cursor.fetchall()

    return render_template("admin/room.html", code=room, messages=messages)


@socketio.on("message")
def message(data):
    print("Received message:", data)  # Debug log
    room = session.get("room")
    if not room:
        return

    content = {
        "name": session.get("name"),
        "message": data["data"],
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    cursor.execute("INSERT INTO messages (room_name, sender_name, message, created_at) VALUES (%s, %s, %s, %s)",
                   (room, content["name"], content["message"], content["created_at"]))
    db.commit()

    socketio.emit("message", content, room=room)
    print(f"{content['name']} said: {content['message']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room:
        cursor.execute("UPDATE rooms SET members_count = members_count - 1 WHERE room_name = %s", (room,))
        db.commit()

        send({"name": name, "message": "has left the room"}, to=room)
        print(f"{name} has left the room {room}")

@app.route("/logout/")
def logout():
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

