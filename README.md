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

# Endpoints
The end points checked are given in the OpenAPI spefication down below:

openapi: 3.0.1
info:
  title: defaultTitle
  description: defaultDescription
  version: "0.1"
servers:
- url: http://localhost:5000
paths:
  /user1/updatePermissions:
    post:
      description: Auto generated using Swagger Inspector
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/body'
            examples:
              "0":
                value: |2

                  {
                      "file_id":"text.txt",
                      "email":"user2@Xgrid.com",
                      "action":"allow"
                  }
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200'
              examples:
                "0":
                  value: |
                    {"permissions":["user1","user2"]}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
  /user1/upload:
    get:
      description: Auto generated using Swagger Inspector
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_1'
              examples:
                "0":
                  value: |
                    {"message":"you have permissions to upload to this server"}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
  /user1/text.txt:
    get:
      description: Auto generated using Swagger Inspector
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_2'
              examples:
                "0":
                  value: |
                    {"url to file":"/Storage/user1/text.txt"}
      servers:
      - url: http://localhost:5000
    delete:
      description: Auto generated using Swagger Inspector
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_1'
              examples:
                "0":
                  value: |
                    {"message":"file deleted"}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
  /signup:
    post:
      description: Auto generated using Swagger Inspector
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/body_1'
            examples:
              "0":
                value: "{\n    \"username\": \"user1\",\n    \"email\":\"user1@Xgrid.com\"\
                  ,\n    \"password\":\"user1user1\"\n    \n}"
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_3'
              examples:
                "0":
                  value: |
                    {"status":"registration completed."}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
  /login/user:
    post:
      description: Auto generated using Swagger Inspector
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/body_2'
            examples:
              "0":
                value: "{\n    \"username\": \"user1\",\n    \"email\":\"user1@Xgrid.com\"\
                  ,\n    \"password\":\"user1user1\"\n    \n}"
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_4'
              examples:
                "0":
                  value: |
                    {"access_token":"eyJhbGciOiJIUzUxMiIsImlhdCI6MTU4Nzk4MDA3NywiZXhwIjoxNTg3OTgzNjc3fQ.eyJlbWFpbCI6InVzZXIxQFhncmlkLmNvbSIsImFkbWluIjowfQ.xr-YAI2iR-0H61r5TtgDuZP4H5lF93kvzn_09nlrHV4FibMmKVxSj886fOAcmqB_5Ixy5AKobOoOZltPLEHnjw","refresh_token":"eyJhbGciOiJIUzUxMiIsImlhdCI6MTU4Nzk4MDA3NywiZXhwIjoxNTg3OTg3Mjc3fQ.eyJlbWFpbCI6InVzZXIxQFhncmlkLmNvbSJ9.sf9bEFi5xdP3g_gQnBFFzDwDfqJ3nF9GCsTQQm3ihUHAjS-FnG0Nv3-Eg6w22A8E6efZTWx9fh7mu1uJ7e7CfA"}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
  /:
    get:
      description: Auto generated using Swagger Inspector
      responses:
        "200":
          description: Auto generated using Swagger Inspector
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/inline_response_200_1'
              examples:
                "0":
                  value: |
                    {"message":"welcome to the server"}
      servers:
      - url: http://localhost:5000
    servers:
    - url: http://localhost:5000
components:
  schemas:
    body_1:
      type: object
      properties:
        password:
          type: string
        email:
          type: string
        username:
          type: string
    body_2:
      type: object
      properties:
        password:
          type: string
        email:
          type: string
        username:
          type: string
    inline_response_200_1:
      type: object
      properties:
        message:
          type: string
    inline_response_200:
      type: object
      properties:
        permissions:
          type: array
          items:
            type: string
    inline_response_200_2:
      type: object
      properties:
        url to file:
          type: string
    inline_response_200_3:
      type: object
      properties:
        status:
          type: string
    inline_response_200_4:
      type: object
      properties:
        access_token:
          type: string
        refresh_token:
          type: string
    body:
      type: object
      properties:
        file_id:
          type: string
        action:
          type: string
        email:
          type: string
  securitySchemes:
    oauth2:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: http://yourauthurl.com
          scopes:
            scope_name: Enter your scopes here









