import express from "express";
import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const indexPath = path.join(process.cwd(), "views", "index.html");
const loadingCssPath = path.join(process.cwd(), "views", "loading.css");

const indexHtml = fs.readFileSync(indexPath, "utf8");
const loadingCss = fs.readFileSync(loadingCssPath, "utf8");

function basicAuth(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="ImageLab AI"');
    return res.status(401).send("Login necessário.");
  }

  try {
    const encodedCredentials = authorization.split(" ")[1];
    const credentials = Buffer.from(encodedCredentials, "base64").toString("utf8");
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
}

app.use(express.json({ limit: "1mb" }));

app.use(basicAuth);

app.get(["/", "/index.html"], (req, res) => {
  res.type("html").send(indexHtml);
});

app.get("/loading.css", (req, res) => {
  res.type("text/css").send(loadingCss);
});

app.post("/api/generate-image", async (req, res) => {
  const prompt = req.body?.prompt?.trim();

  if (!prompt) {
    return res
      .status(400)
      .json({ error: "Informe uma descrição para gerar a imagem." });
  }

  if (!process.env.OPENAI_API_KEY) {
    return res.status(500).json({
      error: "OPENAI_API_KEY não foi configurada no ambiente do servidor.",
    });
  }

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

    return res.json({
      image: `data:image/png;base64,${imageBase64}`,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Não foi possível conectar ao serviço de geração de imagens.",
    });
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
