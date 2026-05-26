from flask import jsonify
import os
import sqlite3
import datetime
import time

class User:

	def __init__(self):
		create = not os.path.exists('database.db')
		self.db = sqlite3.connect('database.db')
		if create:
			self.cursor = self.db.cursor()
			self.create("CREATE TABLE users (email TEXT PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL)")

	def create(self, query=''):
		self.cursor.execute(query)
		self.db.commit()

	def update(self, name, phone, email, username, password):
		if not name or not email or not phone or not username:
			return 'failed'

		cursor = self.db.cursor()
		cursor.execute("SELECT * from users WHERE email=? and password=?",(email, password, ))
		details = cursor.fetchone()  
		if not details:
			return []

		cursor = self.db.cursor() 
		cursor.execute("UPDATE users set name=?, phone=?, username=? where email=?",(name, phone, username, email))
		self.db.commit()

		# Fetch updated details
		cursor.execute("SELECT * from users WHERE username=? and password=?",(username, password, ))
		details = cursor.fetchone() 
		
		if not details:
			return None
		else:
			user = {
				"email": details[0],
				"username": details[1],
				"name": details[2],
				"password": details[3],
				"phone": details[4]
			}
			return user


	def reset_password(self, username, new_password):
		#check if user exists
		cursor = self.db.cursor()
		cursor.execute("SELECT * from users WHERE username=?",(username, ))
		details = cursor.fetchone()  

		if not details:
			return 'failed'

		cursor = self.db.cursor()
		cursor.execute("UPDATE users set password=? where username=?",(new_password, username, ))
		self.db.commit()
		return 'done'

	def register(self, name, email, phone, username, password):
		if not name or not email or not password or not username or not phone:
			return 'failed'

		details = self.login(username, password) 
		if details: 
			return 'user_exits'

		cursor = self.db.cursor() 
		cursor.execute("INSERT INTO users (name, email, phone, password, username) VALUES (?, ?, ?, ?, ?)",(name, email, phone, password, username))
		self.db.commit()
		return 'done'

	def login(self, username, password):
		if not username or not password:
			return 'failed' 

		cursor = self.db.cursor()
		cursor.execute("SELECT * FROM users WHERE username=? AND password=?",(username, password, ))
		details = cursor.fetchone()
  
		print('login details:', details) 
		if not details:
			return None
		else:
			user = {
				"email": details[0],
				"username": details[1],
				"name": details[2],
				"password": details[3],
				"phone": details[4]
			}
			return user 