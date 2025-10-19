import os
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
)
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_marshmallow import Marshmallow
from datetime import datetime, timedelta
from dotenv import load_dotenv
from marshmallow import fields

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app_context = app.app_context()
app_context.push()

# Configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql+psycopg2://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# Initialize extensions
db = SQLAlchemy(app)
api = Api(app)
ma = Marshmallow(app)
jwt = JWTManager(app)

# JWT fijo de la aplicación
# STATIC_JWT = create_access_token(
#     identity="app",
#     expires_delta=False  # token sin expiración
# )

# Endpoint para obtener el token
@app.route("/token", methods=["POST"])
def get_token():
    token = create_access_token(
        identity="app",
        expires_delta=False
    )
    return jsonify(access_token=token)

# Define Blacklist model
class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    #app_token = db.Column(db.String(36), nullable=False)  # UUID length
    blocked_reason = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4/IPv6
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Define Blacklist schema
class BlacklistSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Blacklist
        load_instance = True

blacklist_schema = BlacklistSchema()

# Define Blacklist resource
class BlacklistResource(Resource):
    @jwt_required()
    def post(self):
        # Check for Bearer token
        identity = get_jwt_identity()
        if identity != "app":
            return {"error": "Invalid token identity"}, 403

        # Get JSON data
        data = request.get_json()
        if not data:
            return {'error': 'No data provided'}, 400

        email = data.get('email')
        #app_token = str(APP_UUID)
        blocked_reason = data.get('blocked_reason', '')
        # Get IP address
        ip_address = request.remote_addr

        if not email:
            return {'error': 'email and app_token are required'}, 400

        if len(blocked_reason) > 255:
            return {'error': 'blocked_reason must be at most 255 characters'}, 400

        # Create new blacklist entry
        new_entry = Blacklist(
            email=email,
            blocked_reason=blocked_reason,
            ip_address=ip_address
        )

        try:
            db.session.add(new_entry)
            db.session.commit()
            return {'message': 'Email added to blacklist successfully'}, 201
        except Exception as e:
            db.session.rollback()
            print("Error al agregar email:", e)
            traceback.print_exc()
            return {'error': str(e)}, 500

# Define a simple resource
class HelloWorld(Resource):
    @jwt_required()
    def get(self):
        # Check for Bearer token
        identity = get_jwt_identity()
        if identity != "app":
            return {"error": "Invalid token identity"}, 403
        return {'message': 'Hello World'}

# Define schema for GET response
class BlacklistGetSchema(ma.Schema):
    email = fields.String()
    blocked_reason = fields.String()
    is_blocked = fields.Boolean()

blacklist_get_schema = BlacklistGetSchema()

# Blacklist GET resource
class BlacklistCheckResource(Resource):
    @jwt_required()
    def get(self, email):
        """
        Consulta si un email está en la lista negra global.
        
        Args:
            email (str): Email a verificar
            
        Returns:
            JSON con información sobre si el email está bloqueado y el motivo
        """
        # Verificar token de autorización
        identity = get_jwt_identity()
        if identity != "app":
            return {"error": "Invalid token identity"}, 403
        
        # Validar formato de email básico
        if not email or '@' not in email:
            return {'error': 'Invalid email format'}, 400
        
        # Buscar el email en la base de datos
        blacklist_entry = Blacklist.query.filter_by(email=email).first()
        
        if blacklist_entry:
            # Email está en la lista negra
            return {
                'email': email,
                'is_blocked': True,
                'blocked_reason': blacklist_entry.blocked_reason or 'No reason specified'
            }, 200
        else:
            # Email NO está en la lista negra
            return {
                'email': email,
                'is_blocked': False,
                'blocked_reason': None
            }, 200

# Add resources to API
api.add_resource(BlacklistResource, '/blacklists')
api.add_resource(BlacklistCheckResource, '/blacklists/<string:email>')
api.add_resource(HelloWorld, '/')

if __name__ == '__main__':
    # Crear tablas si no existen
    with app.app_context():
        db.create_all()
    app.run(debug=True)