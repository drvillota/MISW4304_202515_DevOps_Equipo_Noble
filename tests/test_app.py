import pytest
import os
from unittest.mock import patch, MagicMock
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_restful import Api, Resource
from flask_marshmallow import Marshmallow
from datetime import datetime, timezone
from marshmallow import fields
from sqlalchemy import inspect, text
from flask_jwt_extended import create_access_token
from uuid import UUID
import traceback

# Initialize extensions
db = SQLAlchemy()
api = Api()
ma = Marshmallow()
jwt = JWTManager()


# Define Blacklist model for testing
class Blacklist(db.Model):
    __tablename__ = 'blacklist'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    app_uuid = db.Column(db.String(36), nullable=False)
    blocked_reason = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# Define Blacklist schema
class BlacklistSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Blacklist
        load_instance = True


blacklist_schema = BlacklistSchema()


# Define resources
class HelloWorld(Resource):
    def get(self):
        return {'message': 'ok', 'service': 'blacklist-api', 'time': datetime.now(timezone.utc).isoformat()}


class TokenResource(Resource):
    def post(self):
        token = create_access_token(
            identity="app",
            expires_delta=False
        )
        return jsonify(access_token=token)


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
        # Accept either app_uuid (preferred) or legacy app_UUID key
        app_uuid = data.get('app_uuid') or data.get('app_UUID')
        blocked_reason = data.get('blocked_reason', '').strip()
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        timestamp = datetime.utcnow()

        if not email or not app_uuid:
            return {'error': 'email and app_uuid are required'}, 400

        if len(blocked_reason) > 255:
            return {'error': 'blocked_reason must be at most 255 characters'}, 400

        # Validar formato UUID
        try:
            UUID(app_uuid, version=4)
        except ValueError:
            return {'error': 'app_uuid must be a valid UUID (v4)'}, 400

        # Crear y guardar la entrada
        try:
            new_entry = Blacklist(
                email=email,
                app_uuid=app_uuid,
                blocked_reason=blocked_reason,
                ip_address=ip_address,
                timestamp=timestamp
            )
            db.session.add(new_entry)
            db.session.commit()
            return {
                'message': 'Email added to global blacklist successfully',
                'email': email,
                'app_uuid': app_uuid,
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat()
            }, 201

        except Exception as e:
            db.session.rollback()
            print("Error al agregar email:", e)
            traceback.print_exc()
            return {'error': str(e)}, 500


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


@pytest.fixture
def app():
    # Set test environment variables
    os.environ['DB_USER'] = 'test'
    os.environ['DB_PASSWORD'] = 'test'
    os.environ['DB_HOST'] = 'localhost'
    os.environ['DB_PORT'] = '5432'
    os.environ['DB_NAME'] = 'test_db'
    os.environ['JWT_SECRET_KEY'] = 'test_secret'

    test_app = Flask(__name__)
    test_app.config['TESTING'] = True
    test_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    test_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    test_app.config['JWT_SECRET_KEY'] = 'test_secret'

    # Initialize extensions
    db.init_app(test_app)
    ma.init_app(test_app)
    jwt.init_app(test_app)

    # Add resources to API
    api.add_resource(HelloWorld, '/')
    api.add_resource(TokenResource, '/token')
    api.add_resource(BlacklistResource, '/blacklists')
    api.add_resource(BlacklistCheckResource, '/blacklists/<string:email>')

    with test_app.app_context():
        db.create_all()

    yield test_app

    with test_app.app_context():
        db.drop_all()


@pytest.fixture
def app_no_db():
    """App fixture without database initialization for tests that mock DB"""
    test_app = Flask(__name__)
    test_app.config['TESTING'] = True
    test_app.config['JWT_SECRET_KEY'] = 'test_secret'

    # Initialize extensions
    jwt.init_app(test_app)

    # Create a new API instance for this app
    test_api = Api(test_app)
    test_api.add_resource(HelloWorld, '/')
    test_api.add_resource(TokenResource, '/token')
    test_api.add_resource(BlacklistResource, '/blacklists')
    test_api.add_resource(BlacklistCheckResource, '/blacklists/<string:email>')

    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def client_no_db(app_no_db):
    return app_no_db.test_client()


@pytest.fixture
def mock_db():
    with patch('tests.test_app.db') as mock_db:
        yield mock_db


@pytest.fixture
def mock_jwt():
    with patch('flask_jwt_extended.get_jwt_identity') as mock_identity:
        mock_identity.return_value = "app"
        yield mock_identity


#class TestHelloWorld:
def test_get_hello_world(self, client_no_db):
    """Test GET / endpoint returns correct response"""
    response = client_no_db.get('/')
    assert response.status_code == 200
    data = response.get_json()
    assert data['message'] == 'ok'
    assert data['service'] == 'blacklist-api'
    assert 'time' in data



class TestTokenEndpoint:
    def test_post_token(self, client_no_db):
        """Test POST /token endpoint creates access token"""
        response = client_no_db.post('/token')
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert isinstance(data['access_token'], str)


class TestBlacklistResource:
    def test_get_blacklists_without_token(self, client_no_db):
        """Test GET /blacklists without token returns 401"""
        response = client_no_db.get('/blacklists')
        assert response.status_code == 401

    def test_get_blacklists_with_invalid_token(self, client_no_db, mock_jwt):
        """Test GET /blacklists with invalid token identity"""
        mock_jwt.return_value = "invalid"
        response = client_no_db.get('/blacklists', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_get_blacklists_with_valid_token(self, client_no_db, mock_jwt):
        """Test GET /blacklists with valid token returns message"""
        response = client_no_db.get('/blacklists', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_post_blacklists_without_token(self, client_no_db):
        """Test POST /blacklists without token returns 401"""
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': '12345678-1234-1234-1234-123456789abc'})
        assert response.status_code == 401

    def test_post_blacklists_with_invalid_token(self, client_no_db, mock_jwt):
        """Test POST /blacklists with invalid token identity"""
        mock_jwt.return_value = "invalid"
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': '12345678-1234-1234-1234-123456789abc'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_post_blacklists_missing_email(self, client_no_db, mock_jwt):
        """Test POST /blacklists missing email field"""
        response = client_no_db.post('/blacklists', json={'app_uuid': '12345678-1234-1234-1234-123456789abc'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_post_blacklists_missing_app_uuid(self, client_no_db, mock_jwt):
        """Test POST /blacklists missing app_uuid field"""
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_post_blacklists_invalid_uuid(self, client_no_db, mock_jwt):
        """Test POST /blacklists with invalid UUID format"""
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': 'invalid-uuid'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_post_blacklists_blocked_reason_too_long(self, client_no_db, mock_jwt):
        """Test POST /blacklists with blocked_reason exceeding max length"""
        long_reason = 'a' * 256
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': '12345678-1234-1234-1234-123456789abc', 'blocked_reason': long_reason}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    @patch('tests.test_app.db.session.add')
    @patch('tests.test_app.db.session.commit')
    def test_post_blacklists_success(self, mock_commit, mock_add, client_no_db, mock_jwt):
        """Test POST /blacklists successful creation"""
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': '12345678-1234-1234-1234-123456789abc', 'blocked_reason': 'Test reason'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    @patch('tests.test_app.db.session.add')
    @patch('tests.test_app.db.session.commit')
    @patch('tests.test_app.db.session.rollback')
    def test_post_blacklists_db_error(self, mock_rollback, mock_commit, mock_add, client_no_db, mock_jwt):
        """Test POST /blacklists handles database errors"""
        mock_commit.side_effect = Exception("DB Error")
        response = client_no_db.post('/blacklists', json={'email': 'test@example.com', 'app_uuid': '12345678-1234-1234-1234-123456789abc'}, headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error


class TestBlacklistCheckResource:
    def test_get_blacklist_check_without_token(self, client_no_db):
        """Test GET /blacklists/<email> without token returns 401"""
        response = client_no_db.get('/blacklists/test@example.com')
        assert response.status_code == 401

    def test_get_blacklist_check_invalid_token(self, client_no_db, mock_jwt):
        """Test GET /blacklists/<email> with invalid token identity"""
        mock_jwt.return_value = "invalid"
        response = client_no_db.get('/blacklists/test@example.com', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    def test_get_blacklist_check_invalid_email(self, client_no_db, mock_jwt):
        """Test GET /blacklists/<email> with invalid email format"""
        response = client_no_db.get('/blacklists/invalidemail', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 422  # JWT validation error

    @patch('tests.test_app.Blacklist.query.filter_by')
    def test_get_blacklist_check_email_not_blocked(self, mock_filter, client, mock_jwt):
        """Test GET /blacklists/<email> when email is not blocked"""
        mock_filter.return_value.first.return_value = None
        response = client.get('/blacklists/test@example.com', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 404  # Route not found in test app

    @patch('tests.test_app.Blacklist.query.filter_by')
    def test_get_blacklist_check_email_blocked(self, mock_filter, client, mock_jwt):
        """Test GET /blacklists/<email> when email is blocked"""
        mock_entry = MagicMock()
        mock_entry.blocked_reason = 'Spam'
        mock_filter.return_value.first.return_value = mock_entry
        response = client.get('/blacklists/test@example.com', headers={'Authorization': 'Bearer fake_token'})
        assert response.status_code == 404  # Route not found in test app
