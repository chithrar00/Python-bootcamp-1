![Coverage Badge](https://img.shields.io/badge/coverage-100%25-brightgreen) ![build](https://camo.githubusercontent.com/a103c3480970625b5916b80e09f539b3ed2e62083d6a2a3e8dd9969cb97d0578/68747470733a2f2f696d672e736869656c64732e696f2f636972636c6563692f70726f6a6563742f6769746875622f6261646765732f736869656c64732f6d6173746572)

# FastAPI Demo Application

This code defines a FastAPI application with CRUD endpoints for managing a database of items and users. Authentication is implemented using JWT tokens and admin access is required to perform certain operations on users. The database is stored in memory as dictionaries. There are endpoints for creating, retrieving, updating and deleting items and users, as well as a login endpoint that returns a JWT token. There are also endpoints for searching items and retrieving user information.

## Usage

To use this application, run the following commands:

```
make init
make test
make start
```

## Dependencies

This application requires the following dependencies which are listed in `requirements.txt`:

- FastAPI
- PyJWT
- Pydantic
- Uvicorn
- PyTest (with pytest-asyncio, pytest-cov, httpx)

## Endpoints

### Authentication

- `POST /login` - allows a user to log in by providing a username and password. If the credentials are correct, the method returns a JWT token that can be used to authenticate subsequent protected requests. The token is valid for a limited time. The method returns a status code 401 if the username or password is incorrect.

### Items

- `GET /items/{item_id}` - retrieve item information based on the item's ID.
- `GET /items` - get a list of items. You can choose to filter the list by searching for a specific keyword using the query parameter `q`. Additionally, you can limit the number of results shown on each page by using the `limit` parameter, and skip a number of items using the `skip` parameter.
- `POST /items` - adds a new item to the inventory.
- `PUT /items/{item_id}` - revises an item that has already been inventoried by its `item_id`.

### Users

- `POST /users` - creates a new user. **To perform this operation, it is mandatory to have admin access.**
- `GET /users/{username}` - retrieves a user record identified by the `username` (case-insensitive). **To perform this operation, it is mandatory to have admin access.**
- `GET /users` - retrieves all users. **To perform this operation, it is mandatory to have admin access.**
- `PUT /users/{username}` - revises an existing user record. **To perform this operation, it is mandatory to have admin access.**
- `DELETE /users/{username}` - deletes an existing user record. **To perform this operation, it is mandatory to have admin access.**