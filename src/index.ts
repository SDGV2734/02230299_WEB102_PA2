import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { sign } from "hono/jwt";
import axios from "axios";
import { jwt } from "hono/jwt";
import type { JwtVariables } from "hono/jwt";

// Define custom types for Hono context variables
type Variables = JwtVariables;

// Initialize Hono app with custom context types
const app = new Hono<{ Variables: Variables }>();
const prisma = new PrismaClient();

// Apply CORS middleware to all routes
app.use("/*", cors());

// Apply JWT middleware to protected routes
app.use(
  "/protected/*",
  jwt({ secret: "mySecretKey" })
);

// Registration endpoint
app.post("/register", async (c) => {
  try {
    const { email, password } = await c.req.json();

    // Hash password using bcrypt with specified cost
    const bcryptHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 4 });

    // Create a new user in the database
    const user = await prisma.user.create({
      data: { email, hashedPassword: bcryptHash }
    });

    return c.json({ message: `${user.email} created successfully` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return c.json({ message: "Email already exists" });
    }
    console.error("Registration error:", e);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Login endpoint
app.post("/login", async (c) => {
  try {
    const { email, password } = await c.req.json();

    // Fetch user by email
    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, hashedPassword: true }
    });

    if (!user) {
      return c.json({ message: "User not found" }, 404);
    }

    // Verify password using bcrypt
    const isPasswordValid = await Bun.password.verify(password, user.hashedPassword, "bcrypt");

    if (!isPasswordValid) {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }

    // Create JWT token
    const payload = { sub: user.id, exp: Math.floor(Date.now() / 1000) + 3600 }; // 60 minutes expiry
    const token = await sign(payload, "mySecretKey");

    return c.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Fetch Pokémon data from external API
app.get("/pokemon/:name", async (c) => {
  const { name } = c.req.param();

  try {
    const response = await axios.get(`https://pokeapi.co/api/v2/pokemon/${name}`);
    return c.json({ data: response.data });
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 404) {
        return c.json({ message: "Your Pokémon was not found!" }, 404);
      }
      return c.json({ message: "Error fetching Pokémon data" }, 500);
    }
    return c.json({ message: "An unexpected error occurred" }, 500);
  }
});

// Catch and save Pokémon to the database
app.post("/protected/catch", async (c) => {
  const payload = c.get("jwtPayload");

  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  try {
    const { name: pokemonName } = await c.req.json();

    if (!pokemonName) {
      throw new HTTPException(400, { message: "Pokemon name is required" });
    }

    let pokemon = await prisma.pokemon.findUnique({ where: { name: pokemonName } });

    // Create new Pokémon entry if not exists
    if (!pokemon) {
      pokemon = await prisma.pokemon.create({ data: { name: pokemonName } });
    }

    // Record the caught Pokémon for the user
    const caughtPokemon = await prisma.caughtPokemon.create({
      data: {
        userId: payload.sub,
        pokemonId: pokemon.id,
      },
    });

    return c.json({ message: "Pokemon caught", data: caughtPokemon });
  } catch (error) {
    console.error("Catch Pokémon error:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Release Pokémon from the database
app.delete("/protected/release/:id", async (c) => {
  const payload = c.get("jwtPayload");

  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  const { id } = c.req.param();

  try {
    const deleteResult = await prisma.caughtPokemon.deleteMany({
      where: { id, userId: payload.sub },
    });

    if (deleteResult.count === 0) {
      return c.json({ message: "Pokemon not found or not owned by user" }, 404);
    }

    return c.json({ message: "Pokemon is released" });
  } catch (error) {
    console.error("Release Pokémon error:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// List caught Pokémon
app.get("/protected/caught", async (c) => {
  const payload = c.get("jwtPayload");

  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  try {
    const caughtPokemon = await prisma.caughtPokemon.findMany({
      where: { userId: payload.sub },
      include: { pokemon: true },
    });

    if (!caughtPokemon.length) {
      return c.json({ message: "No Pokémon found." });
    }

    return c.json({ data: caughtPokemon });
  } catch (error) {
    console.error("Fetch caught Pokémon error:", error);
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

export default app;
