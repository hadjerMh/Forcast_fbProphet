from flask import redirect, url_for, render_template, request, send_from_directory, flash, abort
from testBM import app, db, bcrypt
import os
import pandas as pd
from fbprophet import Prophet
from testBM.forms import LoginForm, SignUpForm
from testBM.models import User, File
from flask_login import login_user, logout_user, current_user, login_required
from io import BytesIO
import base64
import urllib.parse


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    """
    The signup function renders the form in the signUp page and create users within the database
    """
    # Redirect the user to the home page if he is already login
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = SignUpForm()
    if form.validate_on_submit():
        # Hashing the password and getting the value in string not bytes
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Adding tha user into the database
        user = User(username=form.username.data,
                    email=form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        # Sending a success message
        flash(f"Account {form.username.data} created successfully", 'success')
        return redirect(url_for('login'))
    return render_template("signup.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    Renders the login page and authenticate the user via his email and password that's
    compared to the data on the database.
    """
    # Redirect the user to the home page if he is already login
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            # Check if the email and the password are valid
            if user and bcrypt.check_password_hash(user.password, form.password.data):
                # Use the login_user function to login our user and render a success message
                login_user(user, remember=bool(form.remember.data))
                flash('Login successfully!', 'success')
                return redirect(url_for('home'))
            else:
                # Render an error message
                flash('Failed to login, please check your username or your password', 'danger')
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    """
    The logout function authorize the user to logout and redirect him to the login page
    """
    logout_user()
    return redirect("login")


@app.route("/", methods=['GET', 'POST'])
@login_required
def home():
    """
    The home function renders the home page and get the file that needs to be estimated via the
    post request and the data for the model training.
    """
    if request.method == 'POST':
        f = request.files['filename']
        # Using the get method to support when a checkbox is unchecked
        daily = bool(request.form.getlist('daily'))
        weekly = bool(request.form.getlist('weekly'))
        yearly = bool(request.form.getlist('yearly'))
        period = int(request.form['period'])
        #print(period)
        # Verifying that the file is not empty
        if f:
            # Reading the file
            df = pd.read_csv(f, on_bad_lines='skip')
            # Creating a list with columns header to make sure that we have a ds and y in the columns
            header = [col for col in df.columns]
            if 'ds' and 'y' in header:
                # Verifying that the data is correctly formatted for ds
                if pd.to_datetime(df['ds'], format='%Y-%m-%d').notnull().all():
                    # Creating an instance on the database for the file
                    file = File(userId=current_user.id,
                                originalFileName=f.filename,
                                daily=daily,
                                weekly=weekly,
                                yearly=yearly,
                                period=period)
                    db.session.add(file)
                    try:
                        db.session.commit()
                        # Using the id to have a unique file name so there is no issue in the saving process
                        filename = str(file.id) + "_" + f.filename
                        # Saving the file
                        df.to_csv(os.path.join(app.config['FILE_UPLOADS'], filename))
                        return redirect(url_for("results", fileid=file.id))
                    except:
                        flash("An error occurred please reload your file")
                else:
                    flash('Please verify that all your dates are correctly formatted', 'danger')
            else:
                flash('Please change your column names before importing the file', 'danger')

    return render_template("home.html")


@app.route("/Results/<fileid>")
@login_required
def results(fileid):
    """
    The result function renders the result page, this function does the estimation and generate a csv file
    and figures from that estimation.
    """
    file = File.query.filter_by(id=int(fileid)).first()
    # Raising an error of page not fount so the user can't access data that's not his
    if file.userId == current_user.id:
        # Recreating the file name
        filename = str(file.id) + "_" + file.originalFileName
        path_file = os.path.join(app.config['FILE_UPLOADS'], filename)
        # Reading the csv file
        df = pd.read_csv(path_file)
        # Keeping only the ds and y columns
        df = df[['ds', 'y']]
        # Insuring that the ds column has the right type
        df['ds'] = pd.to_datetime(df['ds'])
        # Instantiating the Prophet object
        m = Prophet(daily_seasonality=file.daily,
                    weekly_seasonality=file.weekly,
                    yearly_seasonality=file.yearly)
        # Fitting the dataframe
        m.fit(df)
        # Forcasting away
        print(file.period)
        future = m.make_future_dataframe(periods=file.period)
        future.tail()
        forecast = m.predict(future)
        # Creating a filename based on the filename with the id in orther for it to be unique
        downloadFilename = 'estimation ' + filename
        fileforcasted = forecast.to_csv(os.path.join(app.config['FILE_DOWNLOAD'], downloadFilename))
        # Adding the estimated filename
        file.estimatedFileName = downloadFilename
        # Plotting the figures
        fig1 = m.plot(forecast)
        fig2 = m.plot_components(forecast)
        # Creating the buffer for the figures
        imgfig1 = BytesIO()
        imgfig2 = BytesIO()
        # Saving the images in the buffer
        fig1.savefig(imgfig1, format='png')
        fig2.savefig(imgfig2, format='png')
        # Seeking the entire file from zero to length file
        imgfig1.seek(0)
        imgfig2.seek(0)
        # Figure URLS
        fig1URL = urllib.parse.quote(base64.b64encode(imgfig1.getvalue()).decode())
        fig2URL = urllib.parse.quote(base64.b64encode(imgfig2.getvalue()).decode())

        # Update the db
        db.session.commit()
        #rendering the csv file in the html
        csvFile = [forecast.to_html()]
        return render_template("results.html", filename=downloadFilename, fig1url=fig1URL, fig2url=fig2URL, data=csvFile)
    else:
        abort(404)


@app.route("/Download/<filename>")
@login_required
def download_csv(filename):
    """this function takes in the filename and return the right csv that needs to be downloaded
    """
    return send_from_directory(app.config['CSV_Download'], filename, as_attachment=True)


@app.route("/FilesEstimated")
@login_required
def filesEstimated():
    """
    This function renders the files associated with the user so he cas view the results when needed
     or directly download the files.
    """
    files = File.query.filter_by(userId=current_user.id).all()
    return render_template("filesEstimated.html", files=files)


# Errors pages
@app.errorhandler(404)
def invalid_route(e):
    """Custom templates for the error 404 page
    """
    return render_template("error404.html")


@app.errorhandler(500)
def invalid_route(e):
    """Custom templates for the error 500 page
    """
    return render_template("error500.html")

# File routes
app.config['FILE_UPLOADS'] = "./testBM/dataStorage"
app.config['FILE_DOWNLOAD'] = "./testBM/dataStorage/FilesToDownload"
app.config['CSV_Download'] = "dataStorage/FilesToDownload"