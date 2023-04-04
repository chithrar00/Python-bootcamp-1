"""
test_main.py

This file contains unit tests for various functions in the main FastAPI application, including user authentication, 
CRUD operations for items and users, and authorization checks. The tests use TestClient and pytest, and include 
parameterized tests and tests for various edge cases.

Usage:
    make init
    make test

Dependencies:
    see requirements.txt
"""

import datetime

from fastapi.testclient import TestClient
from fastapi import HTTPException
import jwt
import pytest

import main

client = TestClient(main.app)

##################
# FIXTURES       #
##################
@pytest.fixture(params=main.users.keys())
def jwt_token_and_user(request):
    test_user = main.users[request.param]
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=main.JWT_EXPIRATION_MINUTES)
    token_payload = {"username": test_user['name'], "admin": test_user["admin"], "exp": expiration}
    yield (jwt.encode(token_payload, main.JWT_SECRET_KEY, algorithm="HS256"), test_user)

@pytest.fixture(params=['alice'])
def jwt_token(request):
    test_user = main.users[request.param]
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=main.JWT_EXPIRATION_MINUTES)
    token_payload = {"username": test_user['name'], "admin": test_user["admin"], "exp": expiration}
    yield jwt.encode(token_payload, main.JWT_SECRET_KEY, algorithm="HS256")

@pytest.fixture(params=['dave'])
def jwt_token_non_admin(request):
    test_user = main.users[request.param]
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=main.JWT_EXPIRATION_MINUTES)
    token_payload = {"username": test_user['name'], "admin": test_user["admin"], "exp": expiration}
    yield jwt.encode(token_payload, main.JWT_SECRET_KEY, algorithm="HS256")

@pytest.fixture
def authorization_header(jwt_token):
    yield {"Authorization": f"Bearer {jwt_token}"}

@pytest.fixture
def authorization_header_non_admin(jwt_token_non_admin):
    yield {"Authorization": f"Bearer {jwt_token_non_admin}"}

##################
# AUTHENTICATION #
##################
@pytest.mark.asyncio
async def test_authenticate_user_valid_token(jwt_token_and_user):
    token, test_user = jwt_token_and_user
    result = await main.authenticate_user(None, authorization=f"Bearer {token}")
    assert isinstance(result, main.User)
    assert result.name == test_user['name']
    assert result.password == test_user['password']
    assert result.admin == test_user['admin']

@pytest.mark.asyncio
async def test_authenticate_missing_space():
    headers = {"authorization": "Bearervalid-token"}
    with pytest.raises(HTTPException):
        await main.authenticate_user(None, **headers)
    
@pytest.mark.asyncio
async def test_authenticate_missing_bearer():
    headers = {"authorization": "bob valid-token"}
    with pytest.raises(HTTPException):
        await main.authenticate_user(None, **headers)

@pytest.mark.asyncio
async def test_authenticate_user_invalid_token():
    headers = {"authorization": "Bearer invalid-token"}
    with pytest.raises(HTTPException):
        await main.authenticate_user(None, **headers)

@pytest.mark.asyncio
async def test_authenticate_user_missing_username():
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=main.JWT_EXPIRATION_MINUTES)
    token_payload = {"username": 'bad actor', "admin": True, "exp": expiration}
    token = jwt.encode(token_payload, main.JWT_SECRET_KEY, algorithm="HS256")
    headers = {"authorization": f"Bearer {token}"}
    with pytest.raises(HTTPException):
        await main.authenticate_user(None, **headers)
    
@pytest.mark.asyncio
async def test_authenticate_admin_user_is_admin(jwt_token_and_user):
    token, test_user = jwt_token_and_user
    if test_user['admin']:
        result = await main.authenticate_admin_user(None, authorization=f"Bearer {token}")
        assert isinstance(result, main.User)
        assert result.name == test_user['name']
        assert result.password == test_user['password']
        assert result.admin == test_user['admin']


@pytest.mark.asyncio
async def test_authenticate_admin_user_is_not_admin(jwt_token_and_user):
    token, test_user = jwt_token_and_user
    if not test_user['admin']:
        with pytest.raises(HTTPException):
            await main.authenticate_admin_user(None, authorization=f"Bearer {token}")
        

def test_login_valid_credentials():
    test_user = main.users['alice']

    response = client.post(
        "/login",
        json={"username": test_user["name"], "password": test_user["password"]}
    )
    assert response.status_code == 200
    assert "token" in response.json()
    assert jwt.decode(response.json()["token"], main.JWT_SECRET_KEY, algorithms=["HS256"])


def test_login_invalid_credentials():
    response = client.post(
        "/login",
        json={"username": "", "password": ""}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}


def test_login_missing_credentials():
    response = client.post("/login", json={})
    assert response.status_code == 422

##################
# ITEMS          #
##################
def test_read_item_by_id_valid_item_id():
    item_id = 1
    item = main.items_database[item_id]
    response = client.get(f"/items/{item_id}")
    assert response.status_code == 200
    assert response.json() == item


def test_read_item_by_id_invalid_item_id():
    item_id = -1
    response = client.get(f"/items/{item_id}")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

def test_search_items_with_query():
    item = main.items_database[1]
    query = "iPhone"
    response = client.get(f"/items?q={query}")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0] == item


def test_search_items_without_query():
    items = main.items_database
    response = client.get(f"/items")
    assert response.status_code == 200
    assert len(response.json()) == len(items)
    assert all(item in items.values() for item in response.json())

@pytest.mark.parametrize("skip, limit", [[0,4],[1,3]])
def test_search_items_with_skip_and_limit(skip, limit):
    items = main.items_database
    response = client.get(f"/items?skip={skip}&limit={limit}")
    
    assert response.status_code == 200
    assert len(response.json()) == limit
    assert all(item in list(items.values())[skip:skip+limit] for item in response.json())

def test_create_item_success(jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    item = main.Item(name="test item", description="Test description", price=15.0, quantity=99)
    next_item_id = max(main.items_database.keys()) + 1
    response = client.post("/items", json=item.dict(), headers=headers)

    assert response.status_code == 200
    assert next_item_id in main.items_database.keys()
    assert all(item.dict()[key] == response.json()[key] for key in item.dict().keys())
    
def test_create_item_success_with_empty_item_database(jwt_token):
    original_items = main.items_database
    main.items_database = {}
    headers = {"Authorization": f"Bearer {jwt_token}"}
    item = main.Item(name="test item", description="Test description", price=15.0, quantity=99)
    next_item_id = max(main.items_database.keys()) + 1 if main.items_database else 1
    response = client.post("/items", json=item.dict(), headers=headers)

    assert response.status_code == 200
    assert next_item_id in main.items_database.keys()
    assert all(item.dict()[key] == response.json()[key] for key in item.dict().keys())
    main.items_database = original_items

def test_update_item_success(authorization_header):
    item_id = 1
    item = main.items_database[item_id]
    updated_item = main.Item(name="test item", description="Test description", price=15.0, quantity=99)
    response = client.put(f"/items/{item_id}", json=updated_item.dict(), headers=authorization_header)

    assert response.status_code == 200
    assert all(updated_item.dict()[key] == response.json()[key] for key in updated_item.dict().keys())
    assert all(updated_item.dict()[key] == main.items_database[item_id][key] for key in main.items_database[item_id].keys())

def test_update_item_not_found(authorization_header):
    item_id = -1    
    updated_item = main.Item(name="test item", description="Test description", price=15.0, quantity=99)
    response = client.put(f"/items/{item_id}", json=updated_item.dict(), headers=authorization_header)

    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}

##################
# USERS          #
##################
def test_create_user_success(authorization_header):
    user = main.User(name="new_user", password="password2", admin=False)
    response = client.post("/users", json=user.dict(), headers=authorization_header)

    assert response.status_code == 200
    assert response.json() == {"message": "User created successfully."}
    assert user.name.lower() in main.users
    assert all(user.dict()[key] == main.users[user.name.lower()][key] for key in main.users[user.name.lower()].keys())


def test_create_user_user_already_exists(authorization_header):
    user = main.User(**main.users['alice'])
    response = client.post("/users", json=user.dict(), headers=authorization_header)

    assert response.status_code == 409
    assert "User already exists." in response.json()["detail"]

def test_create_user_without_admin_failure(authorization_header_non_admin):
    user = main.User(**main.users['alice'])
    response = client.post("/users", json=user.dict(), headers=authorization_header_non_admin)

    assert response.status_code == 401
    assert "Not authorized to perform this action" in response.json()["detail"]

def test_get_user_success(authorization_header):  
    user = main.users['alice']
    response = client.get(f"/users/{user['name']}", headers=authorization_header)

    assert response.status_code == 200
    assert all(user[key] == response.json()[key] for key in response.json().keys())


def test_get_user_not_found(authorization_header):
    username = "nonexistent_user"
    response = client.get(f"/users/{username}", headers=authorization_header)

    assert response.status_code == 404
    assert "User not found." in response.json()["detail"]

def test_get_user_without_admin_failure(authorization_header_non_admin):
    user = main.User(**main.users['alice'])
    response = client.post("/users", json=user.dict(), headers=authorization_header_non_admin)

    assert response.status_code == 401
    assert "Not authorized to perform this action" in response.json()["detail"]

def test_get_all_users_success(authorization_header):    
    response = client.get(f"/users", headers=authorization_header)

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    for user in response.json():
        assert user['name'].lower() in main.users
        real_user = main.users[user['name'].lower()]
        assert all(user[key] == real_user[key] for key in user.keys())

def test_get_all_users_without_admin_failure(authorization_header_non_admin):
    response = client.get("/users", headers=authorization_header_non_admin)

    assert response.status_code == 401
    assert "Not authorized to perform this action" in response.json()["detail"]

def test_update_user_success(authorization_header):
    existing_user = main.users['nancy']
    user = main.User(name="John Doe", password="FakePassword", admin=False)
    response = client.put(f"/users/{existing_user['name']}", json=user.dict(), headers=authorization_header)

    assert response.status_code == 200
    assert response.json() == {"message": "User updated successfully."}
    assert main.users['nancy'] == user.dict()

    main.users['nancy'] = existing_user


def test_update_user_not_found(authorization_header):
    username = "nonexistent_user"
    user = main.User(name="John Doe", password="FakePassword", admin=False)
    response = client.put(f"/users/{username}", json=user.dict(), headers=authorization_header)

    assert response.status_code == 404
    assert "User not found." in response.json()["detail"]

def test_update_user_without_admin_failure(authorization_header_non_admin):
    existing_user = main.users['nancy']
    user = main.User(name="John Doe", password="FakePassword", admin=False)
    response = client.put(f"/users/{existing_user['name']}", json=user.dict(), headers=authorization_header_non_admin)

    assert response.status_code == 401
    assert "Not authorized to perform this action" in response.json()["detail"]

def test_delete_user_success(authorization_header):
    existing_user = main.users['nancy']
    response = client.delete(f"/users/{existing_user['name']}", headers=authorization_header)

    assert response.status_code == 200
    assert response.json() == {"message": "User deleted successfully."}
    assert existing_user['name'].lower() not in main.users

    main.users[existing_user['name'].lower()] = existing_user

def test_delete_user_not_found(authorization_header):
    username = "nonexistent_user"
    response = client.delete(f"/users/{username}", headers=authorization_header)

    assert response.status_code == 404
    assert "User not found." in response.json()["detail"]

def test_delete_user_without_admin_failure(authorization_header_non_admin):
    existing_user = main.users['nancy']
    response = client.delete(f"/users/{existing_user['name']}", headers=authorization_header_non_admin)

    assert response.status_code == 401
    assert "Not authorized to perform this action" in response.json()["detail"]

if __name__ == '__main__': # pragma: no cover
    pytest.main()