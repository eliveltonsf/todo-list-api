import bcrypt from "bcrypt";
import { fastify } from "fastify";
import jwt from "jsonwebtoken";
import { jwtDecode } from "jwt-decode";
import { prisma } from "./lib/prisma";

export interface CreateUserProps {
  email: string;
  name: string;
  password: string;
}

export interface GetUserByIdProps {
  id: string;
}

export interface LoginUserProps {
  email: string;
  password: string;
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

app.post("/login", async (request, response) => {
  const { email, password } = request.body as LoginUserProps;

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return response.status(404).send({ err: "User not found" });
  }

  const currentUser = bcrypt.compareSync(password, user.password);

  if (!currentUser) {
    return response.status(404).send({ err: "Invalid email or password" });
  }

  try {
    const token = jwt.sign({ email: user.email }, "todolistapi", {
      subject: user.id,
      expiresIn: "24h",
    });

    return response.status(201).send({ accessToken: token, name: user.name });
  } catch (error) {
    return response.status(400).send({ msg: "Internal failure", error });
  }
});

interface CreateTaskProps {
  status?: boolean;
  title: string;
  description: string;
}

app.post("/task", async (request, response) => {
  const { description, title, status } = request.body as CreateTaskProps;

  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return response.status(401).send({ message: "Token not found" });
  }

  try {
    const decoded = jwtDecode(token);

    if (decoded.sub) {
      const task = await prisma.task.create({
        data: {
          title,
          description,
          status,
          userId: decoded.sub,
        },
      });
      return response.status(201).send(task);
    }
  } catch (error) {
    return response.status(403).send({ message: "Invalid or expired token" });
  }
});

interface ListAllTaskProps {
  offset: string;
  limit: string;
}

app.get("/task", async (request, response) => {
  const { limit, offset } = request.query as ListAllTaskProps;

  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return response.status(401).send({ message: "Token not found" });
  }

  try {
    const decoded = jwtDecode(token);

    if (decoded.sub) {
      const startIndex = (Number(offset) - 1) * Number(limit);
      const endIndex = startIndex + Number(limit);

      const tasks = await prisma.task.findMany({
        skip: startIndex,
        take: endIndex,
        select: {
          id: true,
          title: true,
          description: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          userId: true,
          User: {
            select: {
              name: true,
              id: true,
            },
          },
        },
        where: {
          userId: decoded.sub,
        },
      });

      const amountItems = await prisma.task.count({
        select: {
          _all: true,
        },
        where: {
          userId: decoded.sub,
        },
      });

      const totalPages = Math.ceil(amountItems._all / Number(limit));

      return response
        .status(201)
        .send({ tasks, amountItems: amountItems._all, totalPages });
    }
  } catch (error) {
    return response.status(403).send({ message: "Invalid or expired token" });
  }
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
