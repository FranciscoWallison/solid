import { FastifyReply, FastifyRequest } from "fastify";

interface Role {
  role: "ADMIN" | "OPERATOR" | "MEMBER" | ("ADMIN" | "OPERATOR" | "MEMBER")[]
}

export function verifyUserRole ({ role: roleToVerify } : Role) {

  return async (
    request: FastifyRequest,
    reply: FastifyReply,
  ) => {
    
    if (!request.user?.sub) {
      return reply
        .code(401)
        .send({ ok: false, message: "Token ausente ou inválido." });
    }

    const allowedRoles = Array.isArray(roleToVerify) ? roleToVerify : [roleToVerify];

    if (!allowedRoles.includes(request.user.role)) {
      return reply
        .code(403)
        .send({ ok: false, message: "Você não tem permissão para acessar este recurso." });
    }
  };
}
