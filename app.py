from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_marshmallow import Marshmallow

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
api = Api(app)
ma = Marshmallow(app)

# Define a simple resource
class HelloWorld(Resource):
    def get(self):
        return {'message': 'Hello World'}

# Add resource to API
api.add_resource(HelloWorld, '/')

if __name__ == '__main__':
    app.run(debug=True)