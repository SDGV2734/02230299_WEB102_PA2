To install dependencies:
```sh
bun install
```

To run:
```sh
bun run dev
```

open http://localhost:3000

# Pokémon API with Hono and Prisma

It is a basic API service project to createHonore user accounts, login, encrypt and update Pokémon withHonore framework and the Prisma ORM. It also involves the use of JWT to ensure that only authorized persons have access to specific routes and is able to use the Pokémon API to GET information regarding the pokémon.

### Features

- Most of the applications require user registration or login where passwords are stored safely with hashing algorithms.


- JWT authentication for protected routes For this, the server will use json web token to validate protected routes.Read the public Pokémon API to get Pokémon details.

- For authenticates user, let the particular Pokémon be caught and released.
- You can see the list of the caught Pokémon.
### Prerequisites

- Node. js v14 or higher.
- Bun for password hashing (can be installed globally).
-  SQL lite server running (or any other supported by Prisma).

## API Endpoints
### Public Endpoints
#### Register a new user
- URL: /register
- Method: POST
- Body: JSON { "email": "user@example.com", "password": "password123" }
- Response: 200 OK with a message or 409 Conflict if the email already exists.
#### User login
- URL: /login
- Method: POST
- Body: JSON { "email": "user@example.com", "password": "password123" }
- Response: 200 OK with a JWT token or 404 Not Found / 401 Unauthorized for invalid credentials.
#### Get Pokémon details
- URL: /pokemon/:name
- Method: GET
- Params: name - The name of the Pokémon.
- Response: 200 OK with Pokémon data or 404 Not Found if the Pokémon is not found.

#### Protected Endpoints
These endpoints require a valid JWT token. Include the token in the **Authorization** header as **Bearer <token>**.

#### Catch a Pokémon
- URL: /protected/catch
- Method: POST
- Body: JSON { "name": "pikachu" }
- Response: 200 OK with caught Pokémon data or 400 Bad Request if the Pokémon name is not provided.

#### Release a caught Pokémon
- URL: /protected/release/:id
- Method: DELETE
- Params: id - The ID of the caught Pokémon.
- Response: 200 OK on success or 404 Not Found if the Pokémon is not owned by the user.

#### List caught Pokémon
- URL: /protected/caught
- Method: GET
- Response: 200 OK with a list of caught Pokémon or 404 Not Found if no Pokémon are found.

