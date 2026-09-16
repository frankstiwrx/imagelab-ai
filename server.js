import express from "express";
import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import { neon } from "@neondatabase/serverless";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

//Comento

dotenv.config();
const sql = neon(process.env.DATABASE_URL);

const app = express();
const PORT = process.env.PORT || 3000;

const indexPath = path.join(process.cwd(), "views", "index.html");
const loadingCssPath = path.join(process.cwd(), "views", "loading.css");

const indexHtml = fs.readFileSync(indexPath, "utf8");
const loadingCss = fs.readFileSync(loadingCssPath, "utf8");

/* function basicAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="ImageLab AI"');
    return res.status(401).send("Login necessário.");
  }

  try {
    const encodedCredentials = authorization.split(" ")[1];
    const credentials = Buffer.from(encodedCredentials, "base64").toString(
      "utf8",
    );
    const separatorIndex = credentials.indexOf(":");

    if (separatorIndex === -1) {
      throw new Error("Credenciais inválidas.");
    }

    const username = credentials.substring(0, separatorIndex);
    const password = credentials.substring(separatorIndex + 1);

    const userIsValid = username === process.env.APP_USER;
    const passwordIsValid = password === process.env.APP_PASSWORD;

    if (userIsValid && passwordIsValid) {
      return next();
    }
  } catch (error) {
    console.error("Erro de autenticação:", error);
  }

  res.setHeader("WWW-Authenticate", 'Basic realm="ImageLab AI"');
  return res.status(401).send("Usuário ou senha inválidos.");
} */

app.use(express.json({ limit: "1mb" }));

app.use(cookieParser());

app.post("/api/register", async (req, res) => {
  try {
    let { username, password } = req.body;

    username = username?.trim().toLowerCase();

    if (!username || !password) {
      return res.status(400).json({
        error: "Usuário e senha são obrigatórios.",
      });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({
        error: "O usuário deve ter entre 3 e 50 caracteres.",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "A senha deve possuir pelo menos 8 caracteres.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await sql`
      INSERT INTO users (
        username,
        password_hash
      )
      VALUES (
        ${username},
        ${passwordHash}
      )
      RETURNING
        id,
        username,
        credits,
        status,
        created_at
    `;

    return res.status(201).json({
      message: "Conta criada. Aguarde a aprovação do administrador.",
      user: result[0],
    });
  } catch (error) {
    console.error("Erro ao cadastrar usuário:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Esse nome de usuário já está sendo utilizado.",
      });
    }

    return res.status(500).json({
      error: "Não foi possível criar a conta.",
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    let { username, password } = req.body;

    username = username?.trim().toLowerCase();

    if (!username || !password) {
      return res.status(400).json({
        error: "Usuário e senha são obrigatórios.",
      });
    }

    const users = await sql`
      SELECT
        id,
        username,
        password_hash,
        credits,
        status,
        is_admin
      FROM users
      WHERE username = ${username}
      LIMIT 1
    `;

    const user = users[0];

    if (!user) {
      return res.status(401).json({
        error: "Usuário ou senha inválidos.",
      });
    }

    const passwordIsValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordIsValid) {
      return res.status(401).json({
        error: "Usuário ou senha inválidos.",
      });
    }

    if (user.status === "pending") {
      return res.status(403).json({
        error: "Sua conta ainda está aguardando aprovação.",
      });
    }

    if (user.status === "rejected") {
      return res.status(403).json({
        error: "Esta conta não foi aprovada.",
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    res.cookie("imagelab_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Login realizado com sucesso.",
      user: {
        id: user.id,
        username: user.username,
        credits: user.credits,
        isAdmin: user.is_admin,
      },
    });
  } catch (error) {
    console.error("Erro no login:", error);

    return res.status(500).json({
      error: "Não foi possível realizar o login.",
    });
  }
});

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies.imagelab_token;

    if (!token) {
      return res.status(401).json({
        error: "Você precisa estar logado.",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const users = await sql`
      SELECT
        id,
        username,
        credits,
        status,
        is_admin
      FROM users
      WHERE id = ${decoded.userId}
      LIMIT 1
    `;

    const user = users[0];

    if (!user) {
      return res.status(401).json({
        error: "Usuário não encontrado.",
      });
    }

    if (user.status !== "approved") {
      return res.status(403).json({
        error: "Sua conta não está aprovada.",
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error("Erro de autenticação:", error);

    return res.status(401).json({
      error: "Sessão inválida ou expirada.",
    });
  }
}

app.get("/api/me", requireAuth, async (req, res) => {
  return res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      credits: req.user.credits,
      isAdmin: req.user.is_admin,
    },
  });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("imagelab_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  return res.json({
    message: "Logout realizado com sucesso.",
  });
});

//app.use(basicAuth);

/* app.get("/api/test-db", async (req, res) => {
  try {
    const result = await sql`
      SELECT
        NOW() AS database_time,
        (SELECT COUNT(*)::int FROM users) AS users_count
    `;

    res.json({
      ok: true,
      databaseTime: result[0].database_time,
      usersCount: result[0].users_count,
    });
  } catch (error) {
    console.error("Erro ao testar banco:", error);

    res.status(500).json({
      ok: false,
      error: "Não foi possível conectar ao banco.",
    });
  }
}); */

app.get(["/", "/index.html"], (req, res) => {
  res.type("html").send(indexHtml);
});

app.get("/loading.css", (req, res) => {
  res.type("text/css").send(loadingCss);
});

app.post("/api/generate-image", requireAuth, async (req, res) => {
  const prompt = req.body?.prompt?.trim();

  if (!prompt) {
    return res.status(400).json({
      error: "Informe uma descrição para gerar a imagem.",
    });
  }

  if (!process.env.OPENAI_API_KEY) {
    return res.status(500).json({
      error: "OPENAI_API_KEY não foi configurada no ambiente do servidor.",
    });
  }

  let updatedUsers;

  try {
    // Desconta 1 crédito de forma atômica
    updatedUsers = await sql`
      UPDATE users
      SET credits = credits - 1
      WHERE
        id = ${req.user.id}
        AND credits > 0
      RETURNING credits
    `;

    if (updatedUsers.length === 0) {
      return res.status(403).json({
        error: "Você não possui créditos suficientes.",
      });
    }
  } catch (error) {
    console.error("Erro ao descontar crédito:", error);

    return res.status(500).json({
      error: "Não foi possível verificar seus créditos.",
    });
  }

  let generationSucceeded = false;

  try {
    const apiResponse = await fetch(
      "https://api.openai.com/v1/images/generations",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        },
        body: JSON.stringify({
          model: "gpt-image-2",
          prompt,
          size: "1024x1024",
          quality: "low",
        }),
      },
    );

    const responseText = await apiResponse.text();

    let data;

    try {
      data = JSON.parse(responseText);
    } catch {
      console.error(
        "Resposta não JSON recebida da OpenAI:",
        responseText.slice(0, 500),
      );

      return res.status(502).json({
        error: "O serviço de geração respondeu em um formato inesperado.",
      });
    }

    if (!apiResponse.ok) {
      console.error("Erro da OpenAI:", data);

      return res.status(apiResponse.status).json({
        error: data?.error?.message || "Erro ao gerar a imagem.",
      });
    }

    const imageBase64 = data?.data?.[0]?.b64_json;

    if (!imageBase64) {
      return res.status(500).json({
        error: "A API respondeu sem uma imagem válida.",
      });
    }

    generationSucceeded = true;

    return res.json({
      image: `data:image/png;base64,${imageBase64}`,
      credits: updatedUsers[0].credits,
    });
  } catch (error) {
    console.error("Erro durante geração:", error);

    return res.status(500).json({
      error: "Não foi possível conectar ao serviço de geração de imagens.",
    });
  } finally {
    // Se nenhuma imagem foi entregue, devolve o crédito
    if (!generationSucceeded) {
      try {
        await sql`
          UPDATE users
          SET credits = credits + 1
          WHERE id = ${req.user.id}
        `;

        console.log(`Crédito devolvido ao usuário ${req.user.username}.`);
      } catch (refundError) {
        console.error("Erro ao devolver crédito:", refundError);
      }
    }
  }
});

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "Rota da API não encontrada.",
  });
});

app.use((error, req, res, next) => {
  console.error(error);

  if (req.path.startsWith("/api/")) {
    return res.status(500).json({
      error: "Erro interno do servidor.",
    });
  }

  return res.status(500).send("Erro interno do servidor.");
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`ImageLab AI rodando em http://localhost:${PORT}`);
  });
}

export default app;
