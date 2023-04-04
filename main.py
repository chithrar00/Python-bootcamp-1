"""
main

This code defines a FastAPI application with CRUD endpoints for managing a database of items and users. 
Authentication is implemented using JWT tokens and admin access is required to perform certain operations 
on users. The database is stored in memory as dictionaries. There are endpoints for creating, retrieving, 
updating and deleting items and users, as well as a login endpoint that returns a JWT token. There are also 
endpoints for searching items and retrieving user information.

Usage:
    make init
    make start

Dependencies:
    see requirements.txt
"""
import datetime
from typing import List

import jwt
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Query, status
from pydantic import BaseModel

##################
# CONFIGURATIONS #
##################
JWT_SECRET_KEY = "mysecretkey"
JWT_EXPIRATION_MINUTES = 30
app = FastAPI()

##################
# IN-MEMORY DB   #
##################
users = {
    "alice": {"name": "Alice", "password": "password1", "admin": True},
    "bob": {"name": "Bob", "password": "password2", "admin": True},
    "charlie": {"name": "Charlie", "password": "password3", "admin": False},
    "dave": {"name": "Dave", "password": "password4", "admin": False},
    "eve": {"name": "Eve", "password": "password5", "admin": False},
    "frank": {"name": "Frank", "password": "password6", "admin": False},
    "grace": {"name": "Grace", "password": "password7", "admin": False},
    "heidi": {"name": "Heidi", "password": "password8", "admin": False},
    "ivan": {"name": "Ivan", "password": "password9", "admin": False},
    "jane": {"name": "Jane", "password": "password10", "admin": False},
    "kevin": {"name": "Kevin", "password": "password11", "admin": False},
    "linda": {"name": "Linda", "password": "password12", "admin": False},
    "mike": {"name": "Mike", "password": "password13", "admin": False},
    "nancy": {"name": "Nancy", "password": "password14", "admin": False},
}

items_database = {
    1:{"name": "Apple iPhone 12 Pro", "description": "The latest iPhone from Apple", "price": 999.0, "quantity": 10},
    2:{"name": "Samsung Galaxy S21", "description": "The latest smartphone from Samsung", "price": 799.0, "quantity": 15},
    3:{"name": "Amazon Echo Dot (3rd Gen)", "description": "A popular smart speaker from Amazon", "price": 39.99, "quantity": 20},
    4:{"name": "Nintendo Switch", "description": "A popular gaming console from Nintendo", "price": 299.99, "quantity": 5},
    5:{"name": "Bose QuietComfort 35 II", "description": "A popular noise-cancelling headphones from Bose", "price": 299.0, "quantity": 8},
    6:{"name": "Apple MacBook Air M1", "description": "The latest MacBook from Apple with M1 chip", "price": 999.0, "quantity": 6},
    7:{"name": "Fitbit Charge 4", "description": "A popular fitness tracker from Fitbit", "price": 149.95, "quantity": 12},
    8:{"name": "Sony Alpha A7 III", "description": "A popular mirrorless camera from Sony", "price": 1799.0, "quantity": 3},
    9:{"name": "DJI Mavic Air 2", "description": "A popular drone from DJI", "price": 799, "quantity": 1}
}

##################
# MODELS         #
##################
class Credentials(BaseModel):
    username: str
    password: str

class Item(BaseModel):
    name: str
    description: str
    price: float
    quantity: int

class User(BaseModel):
    name: str
    password: str
    admin: bool

##################
# MIDDLEWARE     #
##################
async def authenticate_user(request: Request, authorization: str = Header(...)) -> User:
    error = 'Invalid authentication token'
    
    if ' ' not in authorization:
        raise HTTPException(status_code=401, detail=error)
    
    token_type, token_string = authorization.split(' ')
    if token_type.lower() != 'bearer':
        raise HTTPException(status_code=401, detail=error)
    try:
        payload = jwt.decode(token_string, JWT_SECRET_KEY, algorithms=['HS256'])
    except:
        raise HTTPException(status_code=401, detail=error)
    
    username = payload.get("username")
    if not username or username.lower() not in users:
        raise HTTPException(status_code=401, detail=error)
    
    return User(**users[username.lower()])

async def authenticate_admin_user(request: Request, authorization: str = Header(...)) -> User:
    error = "Not authorized to perform this action"
    user = await authenticate_user(request, authorization)
    if not user.admin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=error)
    
    return user

##################
# AUTHENTICATION #
##################
@app.post("/login", tags=["Authentication"], 
          description='allows a user to log in by providing a username and password. ' + \
            'If the credentials are correct, the method returns a JWT token that can be used' + \
            'to authenticate subsequent protected requests. The token is valid for a limited time. ' + \
            'The method returns a status code 401 if the username or password is incorrect. ')
async def login(credentials: Credentials):
    user = users.get(credentials.username.lower())
    if user and user["password"] == credentials.password:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
        token_payload = {"username": credentials.username, "admin": user["admin"], "exp": expiration}
        token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm="HS256")
        return {"token": token}
    else:
        raise HTTPException(status_code=401, detail="Invalid username or password")

##################
# ITEMS          #
##################
@app.get("/items/{item_id}", tags=["Items"], description="Retrieve item information based on the item's ID")
async def read_item_by_id(item_id: int) -> dict:
    if item_id in items_database:
        return items_database[item_id]
    raise HTTPException(status_code=404, detail="Item not found")

@app.get("/items", tags=["Items"], description="Get a list of items. You can choose to filter the list by searching for a specific keyword using the query parameter `q`. Additionally, you can limit the number of results shown on each page by using the `limit` parameter, and skip a number of items using the `skip` parameter.")
async def search_items(q: str = Query(None, min_length=3), skip: int = 0, limit: int = 10) -> List[dict]:
    if q is not None:
        filtered_items = [item for item_id, item in items_database.items() if q.lower() in item["name"].lower()]
    else:
        filtered_items = [item for item_id, item in items_database.items()]

    return filtered_items[skip : skip + limit]

@app.post("/items", tags=["Items"], description="Adds a new item to the inventory")
async def create_item(item: Item, user: User = Depends(authenticate_user)):
    new_id = max(items_database.keys()) + 1 if len(items_database.keys()) > 0 else 1
    items_database[new_id] = item.dict()
    return items_database[new_id]


@app.put("/items/{item_id}", tags=["Items"], description="Revises an item that has already been inventoried by its `item_id`")
async def update_item(item_id: int, item: Item, user: User = Depends(authenticate_user)):
    if item_id not in items_database:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found"
        )
    items_database[item_id] = item.dict()
    return items_database[item_id]

##################
# USERS          #
##################
@app.post("/users", tags=["Users"], description="Creates a new user.<br>**To perform this operation, it is mandatory to have admin access.**")
async def create_user(user: User, admin_user: User = Depends(authenticate_admin_user)):
    if user.name.lower() in users:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists.")
    users[user.name.lower()] = user.dict()
    return {"message": "User created successfully."}

@app.get("/users/{username}", tags=["Users"], description="Retrieves a user record identified by the `username` (case-insensitive).<br>**To perform this operation, it is mandatory to have admin access.**")
async def retrieve_user(username: str, admin_user: User = Depends(authenticate_admin_user)) -> User:
    if username.lower() not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return User(**users[username.lower()])

@app.get("/users", tags=["Users"], description="Retrieves all users.<br>**To perform this operation, it is mandatory to have admin access.**")
async def retrieve_user(admin_user: User = Depends(authenticate_admin_user)) -> List[User]:
    response = [User(**user) for username, user in users.items()]
    return response


@app.put("/users/{username}", tags=["Users"], description="Revises an existing user record<br>**To perform this operation, it is mandatory to have admin access.**")
async def update_user(username: str, user: User, admin_user: User = Depends(authenticate_admin_user)):
    if username.lower() not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    users[username.lower()] = user.dict()
    return {"message": "User updated successfully."}

@app.delete("/users/{username}", tags=["Users"], description="Deletes an existing user record.<br>**To perform this operation, it is mandatory to have admin access.**")
async def delete_user(username: str, admin_user: User = Depends(authenticate_admin_user)):
    if username.lower() not in users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    del users[username.lower()]
    return {"message": "User deleted successfully."}

if __name__ == '__main__': # pragma: no cover
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)