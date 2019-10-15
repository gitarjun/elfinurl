from flask import Flask,render_template, flash, redirect, url_for, session, logging, request, jsonify
from config import Config
#import flask_mail
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
from functools import wraps
import os
import base64
import cPickle
import onetimepass
from time import time
import pyaes
from threading import Thread
import random
import string
import genqr
import grablink

# Importing Forms
from appforms import RegisterForm,LinkForm,ChangePassword


app = Flask(__name__)

#Config MySQL
app.config.from_object(Config)
db = SQLAlchemy(app)

#init SQLLite3
#from sqlitedb import Rootdb
#mysql = MySQL(app)
#mail = flask_mail.Mail(app)

class Rootdb(db.Model):
    # __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    username = db.Column(db.String(25), index=True, unique=True)
    email = db.Column(db.String(50))
    password = db.Column(db.String(25))
    secret = db.Column(db.String(16))
    links = db.relationship('Linkdb', backref = 'owner')

class Linkdb(db.Model):
    # __tablename__='Links'
    id = db.Column(db.Integer, primary_key = True)
    keyword = db.Column(db.String(200), index=True, unique = True)
    link = db.Column(db.String(50000))
    visitors = db.Column(db.Integer)
    owner_id = db.Column(db.Integer,db.ForeignKey('rootdb.id'))



def chk_logged_in(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        if 'logged_in' in session:
            return func(*args,**kwargs)
        else:
            flash("Unauthorized, Please Login","danger")
            session['faild_page'] = func.__name__
            return redirect(url_for('login'))
    return wrapper

def get_reset_password_token(id,expires_in=600):
    encoded_string = cPickle.dumps({'id':id,'time':time(),'exp':expires_in})
    return encrypt(encoded_string)


def verify_reset_password_token(encoded_string):
    try:
        token = cPickle.loads(decrypt(encoded_string))
        if time()-token['time']>token['exp']:
            raise ZeroDivisionError
    except Exception as E:
        return
    return token['id']

def encrypt( raw, key=app.secret_key[-16:]):
    aes = pyaes.AESModeOfOperationCTR(key)
    ciphertext = aes.encrypt(raw)
    ciphertext = ciphertext.encode('hex').replace('\n', '')
    return ciphertext

def decrypt(enc, key=app.secret_key[-16:]):
    enc = enc.decode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    decrypted = aes.decrypt(enc)
    return decrypted

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, sender, recipients, text_body, html_body):
    msg = flask_mail.Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()

def send_password_reset_email(id,username):
    token = get_reset_password_token(username)
    send_email('[MyFlaskApp] Reset Password Request',
               sender=app.config['ADMINS'][0],
               recipients=[str(id)],
               text_body=render_template('email/reset_password.txt',
                                         user=username, token=token),
               html_body=render_template('email/reset_password.html',
                                         user=username, token=token))


## Protection against CSRF attack "http://flask.pocoo.org/snippets/3/" #
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return render_template("403.html")

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Main Home Route #
@app.route('/')
def home():
    return render_template("home.html")


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/<string:username>/<string:keyword>/')
def article(username,keyword):
    user_row = Rootdb.query.filter_by(username=username).first() or 0
    if user_row:
        link = Linkdb.query.filter_by(keyword=keyword).first() or 0
        if link:
            link.visitors += 1
            db.session.commit()
            return redirect(link.link)
    return redirect(url_for('home'))

@app.route('/register',methods=['POST','GET'])
#@app.route('/reset_password/<token>',methods=['POST','GET'])
def register(token=None):

    form = RegisterForm(request.form)
    if token!=None and request.method=="GET":
        if token.find('token=')>-1:
            token = token.replace('token=', '')
        username = verify_reset_password_token(token)
        if username !=None:
            result = Rootdb.query.filter_by(username=username).first() or 0
            if result>0:
                form.name.data = result.name
                form.email.data = result.email
                form.username.data = result.username
                form.name.render_kw['readonly'] = True
                form.email.render_kw['readonly'] = True
                form.username.render_kw['readonly'] = True

    if request.method=="POST" and form.validate():
        if token!=None and token.find('token=')>-1:
            token = token.replace('token=','')

        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        chkbox = request.form.get('2FA_chekbox') != None
        if chkbox:
            secret = session['random']
        else:
            secret = "None"

        if token:
            updated_data = Rootdb.query.filter_by(username==username).first()
            updated_data.password = password
            updated_data.secret = secret
            db.session.commit()
        else:
            _data = Rootdb(name=name, username=username, email=email, password=password,
                                  secret=secret)
            db.session.add(_data)
            try:
                db.session.commit()
            except Exception as E:
                db.session().rollback()
                flash('User with username \"{}\" already Exists in DB'.format(username), 'danger')
                return render_template("register.html", form=form, random=session['random'])

        if token:
            flash("Password changed sucessfully", 'success')
        else:
            flash("Thank you for joining us, You can now log in",'success')

        return redirect(url_for('home'))
    session.clear()
    session['random'] = base64.b32encode(os.urandom(10)).decode('utf-8')
    return render_template("register.html", form=form, random=session['random'])


@app.route('/login',methods=["GET","POST"])
def login():
    if request.method=="POST":
        # GEt form fields
        username = request.form['username']
        password_candidate = request.form['password']
        if request.form.get('2FA_chekbox') != None:
            token_candidate = request.form['token']
        else:
            token_candidate = None

        result = Rootdb.query.filter_by(username = username).first() or 0

        if result:

            password = result.password
            token = result.secret
            if token_candidate != None and token!='None':
                condition = onetimepass.valid_totp(token_candidate, token)
            elif token!='None' and token_candidate == None:
                condition = False
            elif token_candidate != None and token == 'None':
                condition = False
            else:
                condition = True
            #app.logger.info(token)

            #Compare the password
            if sha256_crypt.verify(password_candidate,password) and condition:
                #app.logger.info("Password Matched")
                session['logged_in'] = True
                session['Name'] = result.name
                session['username'] = result.username

                flash("You are now logged in",'success')
                try:
                    return redirect(url_for(session['faild_page']))
                except:
                    return redirect(url_for('dashboard'))

            else:
                error = "Invalid Credentials"
                return render_template('login.html', error=error)
                #app.logger.info("Password Does not Match",error=error)
        else:
            error = "Username not found"
            return render_template('login.html',error=error)
            #app.logger.info("No User",error=error)

    return render_template('login.html')

@app.route('/changepassword',methods=['GET',"POST"])
@chk_logged_in
def change_password():
    form = ChangePassword(request.form)
    if request.method == "POST" and form.validate():
        current_password = form.current_password.data
        confirm = form.confirm.data
        result = Rootdb.query.filter_by(username=session['username']).first() or 0
        if result:
            password = result.password
            if sha256_crypt.verify(current_password, password):
                result.password  = sha256_crypt.encrypt(str(confirm))
                db.session.commit()
                flash("Password Changed Successfully", 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Entered a wrong password"
                return render_template('change_password.html', form=form, error=error)
        else:
            error = "Connection to database failed"
            return render_template('change_password', error=error)
    return render_template('change_password.html', form=form)

@app.route('/logout')
@chk_logged_in
def logout():
    session.clear()
    flash("You are now Logged Out",'success')
    return redirect(url_for('home'))


@app.route("/reset_password_request", methods=["GET","POST"])
def reset_password_request():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))

    return redirect(url_for('home'))

    # if request.method=="POST":
    #     username = request.form['username']
    #     cur = mysql.connection.cursor()
    #     result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
    #     if result>0:
    #         data = cur.fetchone()
    #         email = data['Email']
    #         send_password_reset_email(email,data['username'])
    #         flash('Check your email for the instructions to reset your password',"success")
    #     else:
    #         flash('No such user found', "danger")
    #     return redirect(url_for('login'))
    #
    # return render_template("reset_password_request.html")

# For Dashboard
@app.route("/dashboard", methods=['GET'])
@chk_logged_in
def dashboard():
    form = LinkForm(request.form)
    user_row = Rootdb.query.filter_by(username = session['username']).first()
    list_of_links = []
    for i,each in enumerate(user_row.links):
        list_of_links.append({
            'id' : i+1,
            'keyword': each.keyword,
            'link' : each.link,
            'visitors': each.visitors
        })

    if list_of_links>0:
        return render_template('dashboard.html',links=list_of_links,form=form)
    else:
        msg="No Links Found"
        return render_template('dashboard.html',msg=msg, form=form)

#Delete Article
@app.route("/delete_article/<string:keyword>", methods=['POST'])
@chk_logged_in
def delete_article(keyword):
    user_row = Rootdb.query.filter_by(username=session['username']).first()
    delete_this = Linkdb.query.filter_by(keyword=keyword).first() or 0
    if delete_this!=0 and delete_this in user_row.links:
        db.session.delete(delete_this)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/process',methods=['POST'])
@chk_logged_in
def process():
    keyword = request.form['keyword']
    link = request.form['link']
    # query database for the roodb user #
    user_row = Rootdb.query.filter_by(username=session['username']).first()
    list_of_links = [x.keyword for x in user_row.links]
    if len(list_of_links)==10:
        return jsonify({'error': 'Already reached your limit'})

    if not(keyword and link):
        return jsonify({'error': 'Data Missing'})

    if keyword in list_of_links:
        link_row = Linkdb.query.filter_by(keyword=keyword).first()
        link_row.link = link
        link_row.visitors = 0
        db.session.commit()
        return jsonify({'data': '{} updated'.format(keyword)})
    else:
        _data = Linkdb(keyword=keyword, link=link, visitors=0, owner=user_row)
        db.session.add(_data)
        db.session.commit()
        return jsonify({'data': '{} added to database'.format(keyword)})


### Adding extra security ###
@app.route('/qrcode')
def qrcode():
    # render qrcode for FreeTOTP
    otp_secret = session['random']
    string = 'otpauth://totp/Elfin-url:{0}?secret={1}&issuer=Elfin-url.appspot.com' \
        .format('2FA', otp_secret)

    return genqr.create_emb_qr(string), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/gen_qrcode/<string>')
@chk_logged_in
def gen_qrcode(string):
    if string.find('uth://totp/')==-1:
        string = url_for('home',_external=True)+session['username']+"/{}".format(string)
    return genqr.create_emb_qr(string), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route("/download", methods=['GET','POST'])
def download():
    if request.method == "POST":
        link = request.form['link']
        print(link)
        try:
            obj = grablink.LinkGrab()
        except :
            return render_template('download.html')
        links = obj.getlinks(link)
        to_html = []
        for name,link in links.items():
            file_name = "{} Season {} Episode {} - {}.mp4".format(*name.split('>'))
            dllink = obj.get_gorilla_vid(link)
            try:
                dllink = '/'.join(dllink.split('/')[:-1])+'/'+file_name
            except AttributeError: # Fails to get download link returns None
                pass
            to_html.append({'file_name':file_name,'download_link':dllink})
        return render_template('download.html', to_html=to_html)
    return render_template('download.html')


if __name__=="__main__":
    app.run(debug=True, threaded=True)
