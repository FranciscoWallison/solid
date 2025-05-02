import { FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { InvalidCredentialsError } from "@/services/errors/invalid-credentials.error";
import { makeAuthenticateService } from "@/services/factories/make-authenticate-service";

const authenticateSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export async function authenticate(
  request: FastifyRequest<{ Body: z.infer<typeof authenticateSchema> }>,
  reply: FastifyReply,
) {
  const { email, password } = authenticateSchema.parse(request.body);

  try {
    const { user } = await makeAuthenticateService().execute({ email, password });

    const token = await reply.jwtSign(
      { sub: user.id, role: user.role },
      { expiresIn: "10m" }
    );

    const refreshToken = await reply.jwtSign(
      { sub: user.id },
      { expiresIn: "7d" }
    );

    return reply
      .setCookie("refreshToken", refreshToken, {
        path: "/",
        secure: true,
        sameSite: true,
        httpOnly: true,
      })
      .code(200)
      .send({ ok: true, token });

  } catch (err) {
    if (err instanceof InvalidCredentialsError) {
      return reply.code(401).send({ ok: false, message: err.message });
    }
    console.error(err);
    return reply.code(500).send({ ok: false, message: "Erro interno do servidor." });
  }
}
