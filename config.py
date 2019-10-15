import os
class Config(object):
    SECRET_KEY = 'SECRET_KEY'
  
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///elfinDB.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
