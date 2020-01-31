#-*- coding: utf-8 -*-
import psycopg2
import datetime
import time
import md5
import re
import sys
from functools import wraps
from ldap3 import Server, Connection, ALL #<-----------------------import biblioteka

reload(sys)

from flask import Flask, render_template, url_for, request, session

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
sys.setdefaultencoding('utf-8')

ldap_server = os.environ.get('SERVER')
student=os.environ.get('USERNAME')
port=os.environ.get('PORT')
title=os.environ.get('TITLE')

dn = 'userid={},ou=studenti1,ou=is,ou=vvg,dc=aaa,dc=vvg,dc=hr'
username = None
conn = None
password = None
server = None

conn = psycopg2.connect(host="localhost",database=student,user=student,password=student)

sql_spremi_registraciju = """INSERT INTO korisnik (username, password, ime_prezime) VALUES (%s, %s, %s);"""
sql_podaci_korisnika = """SELECT password, ime_prezime FROM korisnik WHERE username = %s;"""
sql_podaci_prihodi = """SELECT konto, naziv, iznos FROM prihodi;"""
sql_podaci_financije = """SELECT konto, naziv, duguje, potrazuje FROM financije;"""

def set_session_data(username, ime_korisnika):

    session['ime_korisnika'] = ime_korisnika
    session['username'] = username

def check_user(username):

    cur = conn.cursor()
    cur.execute(sql_podaci_korisnika, (username,))
    row = cur.fetchone();   
    return row

def add_user(username, hash, ime_prezime):

    cur = conn.cursor()
    cur.execute(sql_spremi_registraciju, (username, hash, ime_prezime))
    conn.commit()

def password_strength(password):

    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    password_error =  {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }

    if(not password_ok):
        print password_error

    return password_ok


@app.route("/")
def home():

    if(not 'username' in session):
        session['username']=None
        session["ime_korisnika"]="Nitko nije prijavljen."

    return render_template("home.html", naziv=title, ime=session["ime_korisnika"]) 

@app.route("/registracija")
def register():

    return render_template("registracija.html",naziv=title ) 

@app.route("/spremi_registraciju", methods=['POST'])
def store_registration():

    if request.method == 'POST':
        
        username = request.form['username'] 
        password = request.form['password']
        
        if(check_user(username) is not None):
            return render_template("error.html",naziv=title, error="Korisnik "+request.form['ime_prezime']+" već postoji!" )  
        
    return render_template("home.html",naziv=title, ime=session["ime_korisnika"]) 

def requires_role(*role):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not isAuthorized(role[0]):
                return render_template("error.html",naziv=title, error="Niste ovlašteni za pristup traženim podacima!" )  
            return f(*args, **kwargs)
        return wrapped
    return wrapper

@app.route("/autentikacija")
def auth():
    return render_template("login.html",naziv=title ) 

@app.route("/prijava", methods=['POST'])
def do_auth():

    if request.method == 'POST':

        global username
        username = request.form['username']
        global password
        password = request.form['password']

        global server
        server = Server(ldap_server, get_info=ALL)
       
        try:
            conn = Connection(server, dn.format(username), password, auto_bind=True)
        except:
            print "Prijava putem LDAP servera nije uspijela !"
            conn = False    
        
        row = check_user(username)

        if(row is None):
            return render_template("error.html",naziv=title, error="Korisnik nije registriran!")
    
        if(conn): 
            conn.search('ou=is,ou=vvg,dc=aaa,dc=vvg,dc=hr', '(objectclass=account)',attributes=['uid','description'])
            set_session_data(username,row[1])
        else:
            set_session_data("Nitko nije prijavljen.",None)
            return render_template("error.html",naziv=title, error="Lozinka nije ispravna!" )

    return render_template("home.html",ldap_data=conn.entries, naziv=title, ime=session["ime_korisnika"]) 


def isAuthorized(role):

    try:
        conn = Connection(server, dn.format(username), password, auto_bind=True)
    except:
        print "Prijava putem LDAP servera nije uspijela !"
        return False

    if conn:
        conn.search('cn='+role+',cn=RBAC,dc=aaa,dc=vvg,dc=hr', '(objectclass=organizationalRole)',attributes=['roleOccupant'])#
        result = filter(lambda entry: username in entry, conn.entries[0]['roleOccupant'])#
        
        return len(result)>0

    return False

@app.route("/financije")
@requires_role('Financije')#
def show_financije():
   
    curr = conn.cursor()
    curr.execute(sql_podaci_financije)
    rows = curr.fetchall()

    return render_template("financije.html", naziv=title, rows=rows, ime=session["ime_korisnika"]) 

@app.route("/kontroling")
@requires_role('Kontroling')#
def show_prihodi():
   
    curr = conn.cursor()
    curr.execute(sql_podaci_prihodi)
    rows = curr.fetchall()

    return render_template("kontroling.html", naziv=title, rows=rows, ime=session["ime_korisnika"]) 

@app.route("/odjava")
def logout():
    session['username']=None
    session["ime_korisnika"]="Nitko nije prijavljen"
    return render_template("home.html",naziv=title, ime=session["ime_korisnika"]) 

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)