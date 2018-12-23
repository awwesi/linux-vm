from flask import Flask, render_template, request, redirect, flash
from models import Base, User, Place, ShowplaceItem
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, joinedload
from sqlalchemy import create_engine, asc, desc
from flask import session as login_session
from flask import make_response, url_for, jsonify
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import psycopg2
import httplib2
import requests
import json

app = Flask(__name__)
app.secret_key = 'sC5E6Hive1EDC1UrPgWBjiNv'

CLIENT_ID = json.loads(
    open('/var/www/html/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CatalogApp"

# Connect to Database and create database session
engine = create_engine('postgresql://showplacesuser:atrebu1a@localhost:5432/showplacesdb')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# show login with anti-forgery state token
@app.route('/catalog/login')
def showLogin():
    if 'email' in login_session:
        flash("You are already logged in.")
        return render_template('connect.html',
                               login_email=login_session['email'])

    # Create anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in range(12))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# check login
@app.route('/catalog/connect', methods=['POST'])
def userconnect():
    # Validate state token
    if request.form['state'] != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    places = session.query(Place).order_by(asc(Place.name))

    if request.form['email'] and request.form['password']:
        # see if user exists, if it doesn't make a new one
        user_id = getUserID(request.form['email'])
        if not user_id:
            user_id = createUser(request.form['email'],
                                 request.form['password'])
        else:
            # check correct user data, if password is correct
            checkUser = getUserInfo(user_id)
            if not checkUser.verify_password(request.form['password']):
                flash("You are not logged in.")
                return render_template('connect.html',
                                       login_email=None, places=places)

        login_session['email'] = request.form['email']
        login_session['password'] = request.form['password']
        login_session['user_id'] = user_id

        flash("You are successfully logged in.")
        return render_template('connect.html',
                               login_email=request.form['email'],
                               places=places)
    else:
        return "Missing login arguments"
        abort(400)


# logout
@app.route('/catalog/disconnect')
def showLogout():
    access_token = login_session.get('access_token')
    if access_token is None:
        # no google login, disconnect local
        places = session.query(Place).order_by(asc(Place.name))
        del login_session['email']
        del login_session['password']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return render_template('disconnect.html', places=places)

    # disconnect google
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        places = session.query(Place).order_by(asc(Place.name))
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['provider']
        del login_session['email']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return render_template('disconnect.html', places=places)
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# google check login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        # print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        pword = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in range(12))
        user_id = createUser(login_session['email'], pword)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['email']
    output += '!</h1>'
    flash("You are now successfully logged in as %s" % login_session['email'])
    # print "done!"
    return output


# show all places with last edit showplaces
@app.route('/')
def applicationMain():
    places = session.query(Place).order_by(asc(Place.name))
    items = session.query(ShowplaceItem).order_by(desc(ShowplaceItem.name))
    return render_template('showplacesLast.html', items=items, places=places)


# Create a new place
@app.route('/catalog/place/new/', methods=['GET', 'POST'])
def newPlace():
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newPlace = Place(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newPlace)
        session.commit()
        flash('New Place %s Successfully Created' % newPlace.name)
        return redirect(url_for('applicationMain'))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('newPlace.html', places=places)


# Edit a place
@app.route('/catalog/<int:place_id>/<string:place_name>/edit/',
           methods=['GET', 'POST'])
def editPlace(place_id, place_name):
    editedPlace = session.query(
        Place).filter_by(id=place_id).one()
    if 'email' not in login_session:
        return redirect('/login')
    if editedPlace.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to edit this place. Please create your own place in order to "
                "edit.');window.location.href = '/';}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            editedPlace.name = request.form['name']
            session.add(editedPlace)
            session.commit()
            flash('Place successfully edited %s' % editedPlace.name)
            return redirect(url_for('applicationMain'))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('editPlace.html', place=editedPlace,
                               places=places)


# Delete a place
@app.route('/catalog/<int:place_id>/<string:place_name>/delete/',
           methods=['GET', 'POST'])
def deletePlace(place_id, place_name):
    placeToDelete = session.query(
        Place).filter_by(id=place_id).one()
    if 'email' not in login_session:
        return redirect('/login')
    if placeToDelete.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to delete this place. Please create your own place in order "
                "delete.');window.location.href = '/';}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(placeToDelete)
        session.commit()
        flash('%s successfully deleted' % placeToDelete.name)
        return redirect(url_for('applicationMain'))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('deletePlace.html', place=placeToDelete,
                               places=places)


# Show showplaces of a place
@app.route('/catalog/<int:place_id>/<string:place_name>/')
def showShowplaces(place_id, place_name):
    place = session.query(Place).filter_by(id=place_id).one()
    items = session.query(ShowplaceItem).filter_by(
        place_id=place_id).all()
    places = session.query(Place).order_by(asc(Place.name))
    return render_template('showplaces.html', items=items, place=place,
                           places=places)


# Show selected showplace
@app.route('/catalog/<int:place_id>/<string:place_name>/<int:showplace_id>/'
           '<string:showplace_name>/')
def showShowplace(place_id, showplace_id, place_name, showplace_name):
    showplace = session.query(ShowplaceItem).filter_by(id=showplace_id).one()
    places = session.query(Place).order_by(asc(Place.name))
    return render_template('showplace.html', showplace=showplace,
                           places=places)


# Create a new showplace item
@app.route('/catalog/<int:place_id>/<string:place_name>/showplace/new/',
           methods=['GET', 'POST'])
def newShowplaceItem(place_id, place_name):
    if 'email' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    if login_session['user_id'] != place.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to add showplace items to this place. Please create your own "
                "place in order to add items.');window.location.href = '/';}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        newItem = ShowplaceItem(name=request.form['name'],
                                description=request.form['description'],
                                place_id=place_id, user_id=place.user_id)
        session.add(newItem)
        session.commit()
        flash('New Showplace item %s successfully Created' % (newItem.name))
        return redirect(url_for('showShowplaces', place_id=place_id,
                        place_name=place.name))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('newShowplaceitem.html', place_id=place_id,
                               place=place, places=places)


# Edit a showplace item
@app.route('/catalog/<int:place_id>/<string:place_name>/<int:showplace_id>/'
           '<string:showplace_name>/edit', methods=['GET', 'POST'])
def editShowplaceItem(place_id, showplace_id, place_name, showplace_name):
    if 'email' not in login_session:
        return redirect('/login')
    editedItem = session.query(ShowplaceItem).filter_by(id=showplace_id).one()
    place = session.query(Place).filter_by(id=place_id).one()
    if login_session['user_id'] != place.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to edit Showplace items to this place. Please create your "
                "own place in order to edit items.');"
                "window.location.href = '/';}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Showplace Item successfully edited')
        return redirect(url_for('showShowplaces', place_id=place_id,
                        place_name=place.name))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('editShowplaceitem.html', item=editedItem,
                               places=places)


# Delete a showplace item
@app.route('/catalog/<int:place_id>/<string:place_name>/<int:showplace_id>/'
           '<string:showplace_name>/delete', methods=['GET', 'POST'])
def deleteShowplaceItem(place_id, showplace_id, place_name, showplace_name):
    if 'email' not in login_session:
        return redirect('/login')
    place = session.query(Place).filter_by(id=place_id).one()
    itemToDelete = (session.query(ShowplaceItem).filter_by
                    (id=showplace_id).one())
    if login_session['user_id'] != place.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to delete Showplace items to this place. Please create your "
                "own place in order to delete items.');"
                "window.location.href = '/';}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Showplace Item successfully deleted')
        return redirect(url_for('showShowplaces', place_id=place_id,
                                place_name=place.name))
    else:
        places = session.query(Place).order_by(asc(Place.name))
        return render_template('deleteShowplaceitem.html', item=itemToDelete,
                               places=places)


# JSON endpoint
@app.route('/catalog.json')
def get_allJSON():
    places = session.query(Place).options(joinedload(Place.items)).all()
    return jsonify(places=[dict(p.serialize, items=[i.serialize for i in
                           p.items]) for p in places])


def createUser(input_email, input_password):
    newUser = User(email=input_email)
    newUser.hash_password(input_password)
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=input_email).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

if __name__ == "__main__":
    app.run()
