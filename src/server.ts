import bcrypt from "bcrypt";
import { fastify } from "fastify";
import { prisma } from "./lib/prisma";

export interface CreateUserProps {
  email: string;
  name: string;
  password: string;
}

export interface GetUserByIdProps {
  id: string;
}

const app = fastify();

app.post("/", async (request, response) => {
  const { name, email, password } = request.body as CreateUserProps;
  const userExist = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (userExist) {
    return response.status(401).send("User already exists!");
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const user = await prisma.user.create({
    data: {
      email,
      password: hash,
      name,
    },
  });

  return response.status(201).send({ ...user });
});

app.get("/", async (request, response) => {
  const users = await prisma.user.findMany();

  return response.status(201).send({ ...users });
});

app.get("/:id", async (request, response) => {
  const { id } = request.params as GetUserByIdProps;
  const userById = await prisma.user.findUnique({
    where: {
      id,
    },
  });
  return response.status(201).send({ ...userById });
});

app
  .listen({ port: 3333 })
  .then(() => {
    console.log("Server running on port 3333.");
  })
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
