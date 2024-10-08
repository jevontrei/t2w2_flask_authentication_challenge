from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask_bcrypt import Bcrypt
from marshmallow.validate import Length
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, request, abort
app = Flask(__name__)


jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = "Backend best end"


bcrypt = Bcrypt(app)
ma = Marshmallow(app)

# DB CONNECTION AREA

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://tomato:123456@localhost:5432/ripe_tomatoes_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# CLI COMMANDS AREA


@app.cli.command("create")
def create_db():
    db.create_all()
    print("Tables created")


@app.cli.command("seed")
def seed_db():

    movie1 = Movie(
        title="Spider-Man: No Way Home",
        genre="Action",
        length=148,
        year=2021
    )
    db.session.add(movie1)

    movie2 = Movie(
        title="Dune",
        genre="Sci-fi",
        length=155,
        year=2021
    )
    db.session.add(movie2)

    actor1 = Actor(
        first_name="Tom",
        last_name="Holland",
        gender="male",
        country="UK"
    )
    db.session.add(actor1)

    actor2 = Actor(
        first_name="Marisa",
        last_name="Tomei",
        gender="female",
        country="USA"
    )
    db.session.add(actor2)

    actor3 = Actor(
        first_name="Timothee",
        last_name="Chalemet",
        gender="male",
        country="USA"
    )
    db.session.add(actor3)

    actor4 = Actor(
        first_name="Zendaya",
        last_name="",
        gender="female",
        country="USA"
    )
    db.session.add(actor4)

    admin_user = User(
        email="admin@email.com",
        password=bcrypt.generate_password_hash("password").decode("utf-8"),
        admin=True
    )
    db.session.add(admin_user)

    user1 = User(
        email="user1@email.com",
        password=bcrypt.generate_password_hash("password").decode("utf-8")
    )

    db.session.add(user1)

    db.session.commit()

    print("Tables seeded")


@app.cli.command("drop")
def drop_db():
    db.drop_all()
    print("Tables dropped")

# MODELS AREA


class Movie(db.Model):
    __tablename__ = "movies"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String())
    genre = db.Column(db.String())
    length = db.Column(db.Integer())
    year = db.Column(db.Integer())


class Actor(db.Model):
    __tablename__ = "actors"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String())
    last_name = db.Column(db.String())
    gender = db.Column(db.String())
    country = db.Column(db.String())


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable=False)
    password = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean(), default=False)

# SCHEMAS AREA


class MovieSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "genre", "length", "year")


movie_schema = MovieSchema()
movies_schema = MovieSchema(many=True)


class ActorSchema(ma.Schema):
    class Meta:
        fields = ("id", "first_name", "last_name", "gender", "country")


actor_schema = ActorSchema()
actors_schema = ActorSchema(many=True)


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "email", "password")

    # set the password's length to a minimum of 8 characters
    password = ma.String(validate=Length(min=8))


user_schema = UserSchema()
users_schema = UserSchema(many=True)


# ROUTING AREA

@app.route("/")
def hello():
    return "Welcome to Ripe Tomatoes API"


@app.route("/movies", methods=["GET"])
def get_movies():
    stmt = db.select(Movie)
    movies = db.session.scalars(stmt)
    return movies_schema.dump(movies)


@app.route("/actors", methods=["GET"])
def get_actors():
    stmt = db.select(Actor)
    actors = db.session.scalars(stmt)
    return actors_schema.dump(actors)


@app.route("/users", methods=["GET"])
def get_users():
    stmt = db.select(User)
    users = db.session.scalars(stmt)
    return users_schema.dump(users)


# NOW REDO THIS ^^ WITH DYNAMIC ROUTING

# @app.route("/<uhty>", methods=["GET"])
# def get_actors(uhty):
#     stmt = db.select(Actor)
#     actors = db.session.scalars(stmt)
#     return actors_schema.dump(actors)

@app.route("/auth/register", methods=["POST"])
def auth_register():
    # The request data will be loaded in a user_schema converted to JSON. request needs to be imported from
    user_fields = user_schema.load(request.json)

    # Find the user:
    stmt = db.select(User).filter_by(email=user_fields['email'])
    user = db.session.scalar(stmt)
    if user:
        # return an abort msg to inform user. That will end the request:
        return abort(400, description="Email already registered")

    # Create the user object
    user = User()

    # Add the email attribute
    user.email = user_fields["email"]

    # Add the password attribute hashed by bcrypt
    user.password = bcrypt.generate_password_hash(
        user_fields["password"]).decode("utf-8")

    # set the admin attribute to false
    # user.admin = False

    # Add it to the database and commit the changes
    db.session.add(user)
    db.session.commit()

    # create a variable that sets an expiry date
    expiry = timedelta(days=1)

    # create the access token
    access_token = create_access_token(
        identity=str(user.id), expires_delta=expiry)

    # return the user email and the access token
    return jsonify({"user": user.email, "token": access_token})

    # Return the user to check the request was successful
    # return jsonify(user_schema.dump(user))


# routes declaration area, below /auth/register
@app.route("/auth/login", methods=["POST"])
def auth_login():
    # get the user data from the request
    user_fields = user_schema.load(request.json)

    # find the user in the database by email
    stmt = db.select(User).filter_by(email=user_fields['email'])
    user = db.session.scalar(stmt)

    # there is not a user with that email or if the password is no correct send an error
    if not user or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description="Incorrect username and password")

    # create a variable that sets an expiry date
    expiry = timedelta(days=1)

    # create the access token
    access_token = create_access_token(
        identity=str(user.id), expires_delta=expiry)

    # return the user email and the access token
    return jsonify({"user": user.email, "token": access_token})


#
#
#
#
#
#
#
# NOW ADD POST AND DELETE FOR MOVIES TOO vvvvv
#
#
#
#
#
#
#



@app.route("/movies", methods=["POST"])
# Decorator to make sure the jwt is included in the request
@jwt_required()
def movie_create():
    user_id = get_jwt_identity()
    stmt = db.select(User).filter_by(id=user_id)
    user = db.session.scalar(stmt)
    
    # Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")

    # Stop the request if the user is not an admin
    if not user.admin:
        return abort(401, description="Unauthorised user")
    
    # Create a new movie
    movie_fields = movie_schema.load(request.json)

    new_movie = Movie()
    new_movie.title = movie_fields["title"]
    new_movie.genre = movie_fields["genre"]
    new_movie.length = movie_fields["length"]
    new_movie.year = movie_fields["year"]

    # not taken from the request, generated by the server
    # new_movie.date = date.today()

    # add to the database and commit
    db.session.add(new_movie)
    db.session.commit()

    # return the movie in the response
    return jsonify(movie_schema.dump(new_movie))


@app.route("/movies/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_movie(id):
    # get the user id invoking get_jwt_identity
    user_id = get_jwt_identity()

    # Find it in the db
    stmt = db.select(User).filter_by(id=user_id)
    user = db.session.scalar(stmt)

    # Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")

    # Stop the request if the user is not an admin
    if not user.admin:
        return abort(401, description="Unauthorised user")

    # find the movie
    stmt = db.select(Movie).filter_by(id=id)
    movie = db.session.scalar(stmt)

    # return an error if the movie doesn't exist
    if not movie:
        return abort(400, description="Movie doesn't exist")

    # Delete the movie from the database and commit
    db.session.delete(movie)
    db.session.commit()

    # return the movie in the response
    return jsonify(movie_schema.dump(movie)), "delete successful"



#
#
#
#
#
#
#
# NOW ADD POST AND DELETE FOR MOVIES TOO ^^^^^
#
#
#
#
#
#
#

@app.route("/actors", methods=["POST"])
# Decorator to make sure the jwt is included in the request
@jwt_required()
def actor_create():
    user_id = get_jwt_identity()
    stmt = db.select(User).filter_by(id=user_id)
    user = db.session.scalar(stmt)
    
    # Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")

    # Stop the request if the user is not an admin
    if not user.admin:
        return abort(401, description="Unauthorised user")
    
    # Create a new actor
    actor_fields = actor_schema.load(request.json)

    new_actor = Actor()
    new_actor.first_name = actor_fields["first_name"]
    new_actor.last_name = actor_fields["last_name"]
    new_actor.gender = actor_fields["gender"]
    new_actor.country = actor_fields["country"]

    # not taken from the request, generated by the server
    # new_actor.date = date.today()

    # add to the database and commit
    db.session.add(new_actor)
    db.session.commit()

    # return the actor in the response
    return jsonify(actor_schema.dump(new_actor))


@app.route("/actors/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_actor(id):
    # get the user id invoking get_jwt_identity
    user_id = get_jwt_identity()

    # Find it in the db
    stmt = db.select(User).filter_by(id=user_id)
    user = db.session.scalar(stmt)

    # Make sure it is in the database
    if not user:
        return abort(401, description="Invalid user")

    # Stop the request if the user is not an admin
    if not user.admin:
        return abort(401, description="Unauthorised user")

    # find the actor
    stmt = db.select(Actor).filter_by(id=id)
    actor = db.session.scalar(stmt)

    # return an error if the actor doesn't exist
    if not actor:
        return abort(400, description="Actor doesn't exist")

    # Delete the actor from the database and commit
    db.session.delete(actor)
    db.session.commit()

    # return the actor in the response
    return jsonify(actor_schema.dump(actor)), "delete successful"
