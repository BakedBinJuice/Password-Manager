#!/usr/bin/env python3

import sqlite3
from sqlite3 import OperationalError
import hashlib
from getpass import getpass
import sys


print("\nWELCOME TO YOUR PASSWORD MANAGER")


def create_connection(db_name):
	connection = None
	try:
		connection = sqlite3.connect(database=db_name)
		print("Conneciton to SQLite DB successful")
	except Error as e:
		print(f"The error '{e}' occurred")

	return connection


connection = create_connection("passwords")


def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        result_raw = str(cursor.fetchall())
        result = result_raw.strip("[").strip("]").strip("'").strip("(").strip(")").strip(",")
        print(result)
    except OperationalError as e:
        print(f"The error '{e}' occurred")

def dumpPass(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        result_raw = str(cursor.fetchall())
        result = result_raw.strip("[").strip("]").strip("'").strip(",")
        finResult = result.replace("(", "\n")
        finResult = finResult.replace(")", "\n")
        print(finResult)

    except OperationalError as e:
        print(f"The error '{e}' occurred")


create_users_query = """CREATE TABLE IF NOT EXISTS user (
	password TEXT NOT NULL)"""
execute_query(connection, create_users_query)

create_passwords_query = """CREATE TABLE IF NOT EXISTS passwords (
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL)"""
execute_query(connection, create_passwords_query)


def gen_user(connection):
	global password
	password = getpass("Enter your password: ")
	hashed_pass = hashlib.sha256(password.encode('ascii')).hexdigest()
	cursor = connection.cursor()
	try:
		cursor.execute("INSERT INTO user (password) VALUES ('" + hashed_pass + "');")
		connection.commit()
		print("\nYour account has been registered.")
		login(connection)
	except OperationalError as e:
		print(f"The error ' {e} ' occurred")


def login(connection):
    cursor = connection.cursor()
    global log_pass
    log_pass = getpass("Password: ")
    global hashed_pass
    hashed_pass = hashlib.sha256(log_pass.encode('ascii')).hexdigest()
    try:
        cursor.execute("SELECT password FROM user WHERE password = '" + hashed_pass + "'")
        connection.commit()
        if(cursor.fetchone() is not None):
            print("Login Successful")
            menu(connection)


        else:
            print("Invalid Credentials")
            login(connection)

    except OperationalError as e:
        print(f"The error {e} has occurred")


def addPassword(connection):
    cursor = connection.cursor()
    title = input("What is the title of the account you wish to add\n --> ")
    username = input("What is the username of this account\n --> ")
    password = input("What is the password of the account you wish to add\n --> ")

    finalAccountQuery = "INSERT INTO passwords (title, username, password) VALUES ('" + title + "', '" + username + "', '" + password + "');"

    try:
        cursor.execute(finalAccountQuery)
        connection.commit()
        print("Account added")
        menu(connection)

    except OperationalError as e:
        print(f"The error {e} has occured")


def checkIfAccountHasBeenMade(connection):
    checkUserQuery = "SELECT password FROM user"
    cursor = connection.cursor()

    try:
        cursor.execute(checkUserQuery)
        connection.commit()
        if(cursor.fetchone() is not None):
            print("you have already created an account")
            login(connection)

        else:
            print("You have not yet created an account")
            gen_user(connection)
    
    except OperationalError as e:
        print(f"The error {e} has occured")


def menu(connection):
    cursor = connection.cursor()
    print("\nWhat would you like to do?\n")
    option = input("(dump) will dump all your saved passwords\n(add) Will allow you to add an account to the database\n(ctrl + c) Exit program\n --> ")

    try:
        if(option == "dump"):
            dumpQuery = "SELECT * FROM passwords"
            dumpPass(connection, dumpQuery)
            menu(connection)

        elif(option == "add"):
            addPassword(connection)

    except KeyboardInterrupt as e:
        print("EXITING...")


checkIfAccountHasBeenMade(connection)

