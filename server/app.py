#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session['page_views'] = None
        session['user_id'] = None
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        
        if not username or not password:
            return {'error': 'Username and password are required.'}, 422

        user = User.query.filter_by(username=username).first()
        if user:
            return {'error': 'User already exists.'}, 409

        new_user = User(username=username)
        new_user.password_hash = password
        
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id  # Log the user in by saving their ID in the session

        return new_user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {}, 204

        user = db.session.get(User, user_id)
        if not user:
            return {}, 204

        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        if not username or not password:
            return {'error': 'Username and password are required.'}, 422

        user = User.query.filter_by(username=username).first()
        if not user or not user.authenticate(password):
            return {'error': 'Invalid username or password.'}, 401

        session['user_id'] = user.id  # Log the user in by saving their ID in the session

        return user.to_dict(), 200

class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return {}, 204
        return {'error': 'No active session.'}, 401

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
