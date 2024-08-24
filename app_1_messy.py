from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from marshmallow.validate import Length
from datetime import timedelta, date
from flask import Flask, jsonify, request, abort
app = Flask(__name__)


ma = Marshmallow(app)

bcrypt = Bcrypt(app)

jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = "Backend best end"


# DB CONNECTION AREA
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://tomato:123456@localhost:5432/ripe_tomatoes_db"

#
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# create the database object
db = SQLAlchemy(app)


# --------------------------------------------------
# CLI COMMANDS AREA
#

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

    # commit the changes
    db.session.commit()
    print("Tables seeded")


@app.cli.command("drop")
def drop_db():
    db.drop_all()
    print("Tables dropped")

# --------------------------------------------------
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
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    admin = db.Column(db.Boolean(), default=False)

# --------------------------------------------------
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


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User

    # set the password's length to a minimum of 8 characters
    password = ma.String(validate=Length(min=8))


user_schema = UserSchema()
users_schema = UserSchema(many=True)

# --------------------------------------------------
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


# route declaration area, below /cards
@app.route("/auth/signup", methods=["POST"])
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
    user.admin = False

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


@app.route("/auth/signin", methods=["POST"])
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


@app.route("/auth/actors", methods=["POST"])
# Decorator to make sure the jwt is included in the request
@jwt_required()
def card_create():
    # Create a new card
    card_fields = card_schema.load(request.json)

    new_card = Card()
    new_card.title = card_fields["title"]
    new_card.description = card_fields["description"]
    new_card.status = card_fields["status"]
    new_card.priority = card_fields["priority"]

    # not taken from the request, generated by the server
    new_card.date = date.today()

    # add to the database and commit
    db.session.add(new_card)
    db.session.commit()

    # return the card in the response
    return jsonify(card_schema.dump(new_card))


@app.route("/auth/actors/<int:id>", methods=["DELETE"])
@jwt_required()
# Includes the id parameter
def card_delete(id):
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

    # find the card
    stmt = db.select(Card).filter_by(id=id)
    card = db.session.scalar(stmt)

    # return an error if the card doesn't exist
    if not Card:
        return abort(400, description="Card doesn't exist")

    # Delete the card from the database and commit
    db.session.delete(card)
    db.session.commit()

    # return the card in the response
    return jsonify(card_schema.dump(card))
