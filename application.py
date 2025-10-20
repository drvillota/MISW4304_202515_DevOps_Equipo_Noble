import os
import traceback
from uuid import UUID
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

import traceback

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

# Crear las tablas automáticamente al iniciar (incluso en Elastic Beanstalk)
with app.app_context():
    db.create_all()
    
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
    __tablename__ = 'blacklist'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    app_UUID = db.Column(db.String(36), nullable=False)  # UUID length
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
    def get(self):
        identity = get_jwt_identity()
        if identity != "app":
            return {"error": "Invalid token identity"}, 403
        return {"message": "Use POST to add email to blacklist, GET /blacklists/check/<email> to check if blocked"}

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
        app_uuid = data.get('app_UUID')
        blocked_reason = data.get('blocked_reason', '').strip()
        ip_address = request.remote_addr
        timestamp = datetime.utcnow()
        
        if not email or not app_uuid:
            return {'error': 'email and app_UUID are required'}, 400

        if len(blocked_reason) > 255:
            return {'error': 'blocked_reason must be at most 255 characters'}, 400

        # Validar formato UUID
        try:
            UUID(app_uuid, version=4)
        except ValueError:
            return {'error': 'app_UUID must be a valid UUID (v4)'}, 400

        # Crear y guardar la entrada
        try:
            new_entry = Blacklist(
                email=email,
                app_UUID=app_uuid,
                blocked_reason=blocked_reason,
                ip_address=ip_address,
                timestamp=timestamp
            )
            db.session.add(new_entry)
            db.session.commit()
            return {
                'message': 'Email added to global blacklist successfully',
                'email': email,
                'app_UUID': app_uuid,
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat()
            }, 201

        except Exception as e:
            db.session.rollback()
            print("Error al agregar email:", e)
            traceback.print_exc()
            return {'error': str(e)}, 500

# Define a simple resource (public, for health checks)
class HelloWorld(Resource):
    def get(self):
        return {'message': 'ok', 'service': 'blacklist-api', 'time': datetime.utcnow().isoformat()}

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

# Create tables after models are defined
with app.app_context():
    db.create_all()

# Add resources to API
api.add_resource(BlacklistResource, '/blacklists')
api.add_resource(BlacklistCheckResource, '/blacklists/check/<string:email>')
api.add_resource(HelloWorld, '/')

# Ejecutar localmente
if __name__ == '__main__':
    app.run(debug=True)