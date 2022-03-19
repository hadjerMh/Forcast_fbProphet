from flask import redirect, url_for, render_template, request, send_file, send_from_directory, flash
from testBM import app, db, bcrypt
import os
import pandas as pd
from fbprophet import Prophet
from testBM.forms import LoginForm, SignUpForm
from testBM.models import User, File
from flask_login import login_user, logout_user, current_user, login_required
import csv


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    # Redirect the user to the home page if he is already login
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = SignUpForm()
    if form.validate_on_submit():
        # hashing the password and getting the value in string not bytes
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # adding tha user into the database
        user = User(username=form.username.data,
                    email=form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f"Account {form.username.data} created successfully", 'success')
        return redirect(url_for('login'))
    return render_template("signup.html", title="Sign Up", form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    # Redirect the user to the home page if he is already login
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            # Check if the email and the password are valid
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                # Use the login_user function to login our user
                login_user(user, remember=bool(form.remember.data))
                flash('Login successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Failed to login, please check your username or your password', 'danger')
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect("login")

@app.route("/", methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        print("function")
        f = request.files['filename']
        daily = bool(request.form.getlist('daily'))
        weekly = bool(request.form.getlist('weekly'))
        yearly = bool(request.form.getlist('yearly'))

        if f:
            df = pd.read_csv(f, on_bad_lines='skip')
            header = [col for col in df.columns]
            if 'ds' and 'y' in header:
                if pd.to_datetime(df['ds'], format='%Y-%m-%d').notnull().all():
                    print(f.save(os.path.join(app.config['FILE_UPLOADS'], f.filename)))
                    file = File(userId=current_user.id,
                                originalFileName=f.filename,
                                daily=daily,
                                weekly=weekly,
                                yearly=yearly)
                    db.session.add(file)
                    db.session.commit()
                    filename = str(file.id) + "_" + f.filename
                    df.to_csv(os.path.join(app.config['FILE_UPLOADS'], filename))
                    return redirect(url_for("results", fileid=file.id))
                else:
                    flash('Please verify that all your dates are correctly formatted', 'danger')
            else:
                flash('Please change your column names before importing the file', 'danger')

    return render_template("home.html")


@app.route("/Results/<fileid>")
@login_required
def results(fileid):
    file = File.query.filter_by(id=int(fileid)).first()
    print(file)
    filename = str(file.id) + "_" + file.originalFileName
    path_file = os.path.join(app.config['FILE_UPLOADS'], filename)
    df = pd.read_csv(path_file)
    df = df[['ds', 'y']]
    df['ds'] = pd.to_datetime(df['ds'])
    #instantiating the Prophet object
    #=False, yearly_seasonality=False
    m = Prophet(daily_seasonality=file.daily,
                weekly_seasonality=file.weekly,
                yearly_seasonality=file.yearly)
    #fitting the dataframe
    m.fit(df)
    future = m.make_future_dataframe(periods=365)
    future.tail()
    forecast = m.predict(future)
    downloadFilename = 'estimation ' + filename
    downloadFile = forecast.to_csv(os.path.join(app.config['FILE_DOWNLOAD'], downloadFilename))
    file.estimatedFileName = downloadFilename
    print('file', downloadFile)
    fig1 = m.plot(forecast)
    fig2 = m.plot_components(forecast)
    nameFig1 = os.path.splitext(filename)[0] + "Fig1.png"
    nameFig2 = os.path.splitext(filename)[0] + "Fig2.png"
    file.fig1Name = nameFig1
    file.fig2Name = nameFig2
    fig1.savefig(os.path.join(app.config['FIGURES'], nameFig1))
    fig2.savefig(os.path.join(app.config['FIGURES'], nameFig2))
    db.session.commit()
    return render_template("results.html", fig1=nameFig1, fig2=nameFig2, filename=downloadFilename)

@app.route("/file/<filename>")
@login_required
def send_file(filename):
    return send_from_directory(app.config['FIGURES_DOWNLOAD'], filename, as_attachment=True)

@app.route("/Download/<filename>")
@login_required
def download_csv(filename):
    return send_from_directory(app.config['CSV_Download'], filename, as_attachment=True)

@app.route("/FilesEstimated")
@login_required
def filesEstimated():
    files = File.query.filter_by(userId=current_user.id).all()
    return render_template("filesEstimated.html", files=files)

app.config['FILE_UPLOADS'] = "./testBM/dataStorage"
app.config['FILE_DOWNLOAD'] = "./testBM/dataStorage/FilesToDownload"
app.config['FIGURES'] = "./testBM/dataStorage/figures"
app.config['FIGURES_DOWNLOAD'] = "dataStorage/figures"
app.config['CSV_Download'] = "dataStorage/FilesToDownload"