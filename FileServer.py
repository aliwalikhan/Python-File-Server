from flask import Flask, request, url_for, abort, g

from flask_sqlalchemy import SQLAlchemy


from passlib.apps import custom_app_context as pwd_context

from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as JWT

from werkzeug.utils import secure_filename 

import json
import os
import shutil


#defining app and static folder.
app = Flask(__name__,static_folder = '/Storage') #defining app name.
#base directory for app to be where the app file is
basedir = os.path.abspath(os.path.dirname(__file__)) #initializing directory path.


#DB CONFIGURATION
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #making it less painful to make modifications in the database.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'db.sqlite') #storing db in the same path as ap.
db = SQLAlchemy(app) #db object.


app.config['UPLOAD_FOLDER'] = "D:\\RandStuff\\Storage" #folder to obtain uploaded files to move to respective directories.


#AUTHORIZATION STUFF WITH TOKENS
jwt = JWT('top secret!', expires_in=3600) #simple access token.
# Refresh token creation.
refresh_jwt = JWT('telelelele', expires_in=7200) #refresh token.
# Auth object creation.
auth = HTTPTokenAuth('Bearer') #auth object to use for login authentication.



#DEFINING OBJECTS TO BE USED
class User(db.Model):
    #define db model
    user_id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(16),unique=True)
    email = db.Column(db.String(64),unique=True)
    user_role = db.Column(db.String(8))
    password_hash = db.Column(db.String(255))
    storage_location = db.Column(db.String(255),unique=True)
    files = db.relationship('File',backref='owner')
    
    
    #verify hashed password
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    

    #generate access token.
    def generate_auth_token(self, permission_level):
        # Check if admin.
        if permission_level == 1:
            # Generate admin token with flag 1.
            token = jwt.dumps({'email': self.email, 'admin': 1})
            # Return admin flag.
            return token
            # Check if admin.
        
        # Return normal user flag.
        return jwt.dumps({'email': self.email, 'admin': 0})
    
    #verify access token.
    @auth.verify_token
    def verify_auth_token(token):
        # Create a global none user.
        g.user = None
        try:
            # Load token.
            data = jwt.loads(token)
        except:
            # If any error return false.
            return False
        # Check if email and admin permission variables are in jwt.
        if 'email' and 'admin' in data:
            # Set email from jwt.
            g.user = data['email']
            return True
        # If does not verified, return false.
        return False
    
    
#adding the ability to store a list as a db entry for permissions.
class Json(db.TypeDecorator):

    impl = db.String

    def process_bind_param(self, value, dialect):
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        return json.loads(value)
    
#file object
class File(db.Model): 
    file_key = db.Column(db.Integer,primary_key=True)
    file_id = db.Column(db.String(128), unique=True)
    file_path = db.Column(db.String(32),unique=True)
    file_owner = db.Column(db.String(32),db.ForeignKey('user.username'))
    file_permissions = db.Column(Json(256)) #list 
    
    
    
#INITIALIZING DB
db.create_all() 

#CREATIGN ADMIN
admin = User(username='admin',
             email='awkhan267@gmail.com',
             user_role = 'admin', 
             password_hash = pwd_context.encrypt('root'),
             storage_location = "D:\\XgridStuff\\Storage" + "\\admin")

try:
    admin_storage_location = "D:\\XgridStuff\\Storage" + "\\admin"
    os.mkdir(admin_storage_location)
    db.session.add(admin)
    db.session.commit()
    print("new admin created")
except:
    pass


print("Starting Server")



@app.route('/',methods=['GET'])
def hello():
    return {"message":"welcome to the server"}



#signup route.
@app.route('/signup',methods=['POST'])   
def sign_up():
    #getting data.
    sentData = request.get_json()
    
    #extracting data.
    username = sentData["username"]
    email = sentData["email"]
    password_hash = pwd_context.encrypt(sentData["password"]) #hashing password to store in db securely.
    user_role = "normal" #only normal users register through here.
    storage_location = "D:\\XgridStuff\\Storage\\" + username
    #basic checks for bad input.
    if username is None or password_hash is None or email is None:
        abort(400) #arguments missing
    #basic checks for already existing user.
    if User.query.filter_by(username=username).first() is not None: 
        abort(409) #user alrdy exists
    #creating new user.
    newUser = User(username=username,email=email,password_hash=password_hash,user_role=user_role,storage_location = storage_location)
    #creating directory and adding to database.
    os.mkdir(storage_location)
    db.session.add(newUser)
    db.session.commit()
    db.session.close()
    return {'status': 'registration completed.'}
    

#login route for regular users.
@app.route('/login/user',methods=['POST'])
def login_user():
    #getting data.
    sentData = request.get_json()
    
    #extracting data.
    email = sentData["email"]
    password = sentData["password"]
    password_hash = pwd_context.encrypt(sentData["password"])
    #checking if user exists in db.
    user = User.query.filter_by(email=email).first() 
    #checking if user doesn't return empty.
    if user is not None:
        #checking if password given is correct.
        if(pwd_context.verify(password,password_hash) == True):
            access_token = user.generate_auth_token(0) #generating auth token with admin = 0 denoting user privilege only for RBAC.
            
            #refresh token generation
            refresh_token = refresh_jwt.dumps({'email': email}) #generating refresh token.
            
            return {'access_token': access_token.decode(), 'refresh_token': refresh_token.decode()} #transferring auth token back.

#login route for admins.
@app.route('/login/admin',methods=['POST'])
def login_admin():
    #getting data.
    sentData = request.get_json()
    
    #extracting data.
    email = sentData["email"]
    password = sentData["password"]
    password_hash = pwd_context.encrypt(sentData["password"])
    #checking if user exists in db.
    user = User.query.filter_by(email=email).first() 
    #checking if user does not return empty.
    if user is not None:
        #checking if password given is correct.
        if(pwd_context.verify(password,password_hash) == True):
            access_token = user.generate_auth_token(1) #generating auth token with admin =1 denoting admin privileges for RBAC.
            
            #refresh token generation
            refresh_token = refresh_jwt.dumps({'email': email}) #generating refresh token.
            
            return {'access_token': access_token.decode(), 'refresh_token': refresh_token.decode()} #transferring auth token back.
    
#upload route for users.
@app.route('/<username>/upload',methods=['GET','POST'])
@auth.login_required #checks if user is logged in
def upload(username):
    #get method to check if you have uploading access or not.
    if (request.method == 'GET'):
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        #checking if the owner is uploading or an admin.
        if (my_username == username or my_role == 1):
            return{"message":"you have permissions to upload to this server"} 
        else:
            return{"message":"you do not have permissions to upload to this server"}
    
    #post method to upload file to server.
    if (request.method == 'POST'):
        #RBAC verification
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        #checking if the owner is uploading or an admin.
        if (my_username == username or my_role == 1):
             #checking if file is coming with request.
             if 'file' not in request.files:
                 return {"message": "file not present"}
             file = request.files['file'] #obtaining file with name = 'file'
             #checking if filename is empty or not.
             if file.filename == '':
                return {"message": "file not present"}
             #uploading file to server.
             if file:
                filename = secure_filename(file.filename) #using secure_filename because everyone was doing it on the internet lol.
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) #getting path to the upload server.
                file.save(upload_path) #saving file to the upload server.
                #moving to user storage folder.
                final_path = user.storage_location + "\\" + filename #getting path for user folder.
                shutil.move(upload_path,final_path) #moving to user folder.
                
                #adding file to db.
                my_file = File(file_id = filename,file_path=final_path, file_owner=my_username, file_permissions=[my_username]) 
                db.session.add(my_file)
                db.session.commit()
                return {"message":"file uploaded successfully"}
        else:
            return{"message":"you do not have permissions to upload to this server"}


#update permissions function as specified.
@app.route('/<username>/updatePermissions',methods=['POST'])
@auth.login_required #checks if user is logged in
def update_permissions(username):
    #post to get a json body which includes the 3 inputs of the function (emailID, fileID, action)
    if (request.method == 'POST'):
        
        #RBAC verification
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        #checking if the owner is uploading or an admin.
        if (my_username == username or my_role == 1):
            #get POSTED data    
            sentData = request.get_json()
            file_id = sentData["file_id"]
            user_email = sentData["email"]
            action = sentData["action"]
            
            #filter out user to give access to
            user = User.query.filter_by(email=user_email).first()
            user_username = user.username 
            #filter out file by file_id 
            file = File.query.filter_by(file_id=file_id).first()
    
            #update permissions
            if (action == "allow"):
                file.file_permissions.append(user_username)
                return {"permissions":file.file_permissions}
            elif (action == "revoke"):
                if user.username in file.file_permissions:
                    file.file_permissions.remove(user_username)
                    return {"permissions":file.file_permissions}
        
                return {"permissions":file.file_permissions}
            else: 
                return {"message":"bad action"}
        else:
            return {"message":"you are not authorized to give access to files you did not upload"}
    




#VIEW, DELETE, UPDATE FILE
@app.route('/<username>/<file_name>', methods = ['GET','PUT','DELETE'])
@auth.login_required #checks if user is logged in
def action(username,file_name):
    #get request to VIEW file.
    if (request.method == 'GET'):
        #RBAC verification.
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        
        file = File.query.filter_by(file_id=file_name).first()    
        # return{"permissions":file.file_permissions}
        
        if (my_username in file.file_permissions or my_role==1):
            return {"url to file":url_for('static', filename=username+'/'+file_name)}
        else:
            return {"message":"you do not have permission to access this file"}
    
    #delete request to DELETE file
    if (request.method == 'DELETE'):
        #RBAC verification.
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        
        file = File.query.filter_by(file_id=file_name).first()    
        # return{"permissions":file.file_permissions}
        if (my_username in file.file_permissions or my_role==1):
            os.remove(file.file_path)
            db.session.delete(file)
            db.session.commit()
            return {"message": "file deleted"}
        else:
            return {"message":"you do not have permission to delete this file"}

    #put request to UPDATE file.
    if (request.method == 'PUT'):
        #RBAC verification.
        #getting access token to decode for RBAC.
        my_token = ''
        authtype, my_token = request.headers['Authorization'].split(None,1) #getting full token body from Authorization header.
        data = jwt.loads(my_token) #decoding token to get values.
        email = data["email"] #extracting email data from token.
        user = User.query.filter_by(email=email).first() #verifying decoded info from data base.
        my_username = user.username #my_username denotes person trying to access route.
        my_role = data["admin"] #extracting admin privilege status from token data.
        
        
        file = File.query.filter_by(file_id=file_name).first()      
        
        if (my_username in file.file_permissions or my_role==1):
             
            if 'file' not in request.files:
                return {"message": "file not present"}
            new_file = request.files['file']
             
            if new_file.filename == '':
               return {"message": "file not present"}
            
            if new_file:
               filename = secure_filename(new_file.filename)
               if (filename == file_name):
                   upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                   new_file.save(upload_path)
                   final_path = user.storage_location + "\\" + filename
                   shutil.move(upload_path,final_path)
                
                   #adding file to dob
                   return {"message":"file uploaded successfully"}
    
        else:
            return {"message":"you do not have permissions to update"}
    

if __name__ == "__main__":
    app.run(debug=False)
