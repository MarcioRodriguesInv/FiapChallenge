# SDK Anti-Fraude - Backend

Este é o backend do SDK anti-fraude desenvolvido para o desafio FIAP/NexShop.

## Instalação
1. Certifique-se de ter o Node.js instalado (versão LTS).
2. Clone este repositório ou crie uma pasta e copie os arquivos.
3. No terminal, na pasta do projeto, rode:

npm init -y
npm install express cors

4. Coloque o `users.json` na pasta com os dados dos usuários.

## Uso
- Rode o servidor com:

node index.js

- O servidor estará disponível em `http://localhost:3000`.

## Endpoint
- **POST /identity/verify**
- **Envia**: JSON com:

{
"username": "string",
"ip": "string",
"device": "string",
"timeOnPage": number,
"visitorId": "string",
"userAgent": "string",
"language": "string",
"timezone": "string"
}

- **Recebe**: JSON com:

{
"action": "allow" | "review" | "deny",
"score": number,
"reason": "string"
}

- **Exemplo de uso**: Use `fetch` ou Postman pra enviar os dados.

## Funções
- Verifica usuário no `users.json`.
- Compara IP, fingerprint (via `deviceValidation.js`) e tempo na página.
- Retorna ação e score baseados nas regras.

## Callbacks
- Se `action` for "review", o front pode pedir autenticação multifator.
- Se `action` for "deny", o front deve bloquear o acesso.

## Observações
- O `users.json` deve ter `firstLoginData` com `ip`, `device`, etc.
- Ajuste `timeOnPage` no `test.html` pra testar diferentes cenários.