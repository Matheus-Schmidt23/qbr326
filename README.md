# QBR Q3 2026 · acesso por senha

Site no Vercel que protege a apresentação do QBR com senha.

- `api/index.js`: tela de login e entrega do conteúdo, só após a senha correta.
- `private/deck.enc`: apresentação criptografada (AES-256). Só o servidor consegue abri-la, com a senha da variável de ambiente `QBR_PASSWORD`.
- A senha não está neste repositório.
