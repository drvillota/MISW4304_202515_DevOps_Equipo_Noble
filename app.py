from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_marshmallow import Marshmallow
from datetime import datetime

app = Flask(__name__)

# Configuration
# For AWS RDS, replace with your RDS connection string
# Example: 'postgresql://username:password@rds-endpoint:5432/database_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # Change this to RDS URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
api = Api(app)
ma = Marshmallow(app)

# Define Blacklist model
class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    app_uuid = db.Column(db.String(36), nullable=False)  # UUID length
    blocked_reason = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4/IPv6
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Define Blacklist schema
class BlacklistSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'app_uuid', 'blocked_reason', 'ip_address', 'timestamp')

blacklist_schema = BlacklistSchema()

# Define Blacklist resource
class BlacklistResource(Resource):
    def post(self):
        # Check for Bearer token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return {'error': 'Unauthorized'}, 401

        token = auth_header.split(' ')[1]
        # For simplicity, use a static token
        if token != 'static-bearer-token':
            return {'error': 'Invalid token'}, 401

        # Get JSON data
        data = request.get_json()
        if not data:
            return {'error': 'No data provided'}, 400

        email = data.get('email')
        app_uuid = data.get('app_uuid')
        blocked_reason = data.get('blocked_reason', '')

        if not email or not app_uuid:
            return {'error': 'email and app_uuid are required'}, 400

        if len(blocked_reason) > 255:
            return {'error': 'blocked_reason must be at most 255 characters'}, 400

        # Get IP address
        ip_address = request.remote_addr

        # Create new blacklist entry
        new_entry = Blacklist(
            email=email,
            app_uuid=app_uuid,
            blocked_reason=blocked_reason,
            ip_address=ip_address
        )

        try:
            db.session.add(new_entry)
            db.session.commit()
            return {'message': 'Email added to blacklist successfully'}, 201
        except Exception as e:
            db.session.rollback()
            return {'error': 'Failed to add email to blacklist'}, 500

# Define a simple resource
class HelloWorld(Resource):
    def get(self):
        return {'message': 'Hello World'}

# Add resources to API
api.add_resource(BlacklistResource, '/blacklists')
api.add_resource(HelloWorld, '/')

if __name__ == '__main__':
    app.run(debug=True)