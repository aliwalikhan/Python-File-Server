# Introduction
This is a RESTful API file server implemented in Python via Flask. 
It employs OAuth2.0 verification & role based access control (RBAC) to Upload, View, Update & Delete files.
The database used was SQLite3 via SQLAlchemy for its exceptional compatibility with Flask.

# Setup
Swagger Inspector and Postman were used to test the endpoints, with the former being used specifically for OpenAPI 3.0 Specification.

Swagger Inspector can be accessed directly from the browser via: https://inspector.swagger.io/builder
Postman can be dowloaded from: https://www.postman.com/tools

Place the files in the following folder: "D:\XgridStuff". If the directory does not exist, create it.
Run the server by via 'python FileServer.py' from the windows command prompt or your IDE.
The server is hosted on http://localhost:5000/
