<?php

declare(strict_types=1);

namespace Alura\Mvc\Controller;

class LoginController implements Controller
{
    private  \PDO $pdo;

    public function __construct()
    {
        $dbPath = __DIR__ . '/../../banco.sqlite';
        $this->pdo = new \PDO("sqlite:$dbPath");
    }

    public function processaRequisicao(): void
    {
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $password = filter_input(INPUT_POST, 'password');

        $sql = 'SELECT * FROM users WHERE email = ?';
        $statemet = $this->pdo->prepare($sql);
        $statemet->bindValue(1, $email);
        $statemet->execute();

        $userData = $statemet->fetch(\PDO::FETCH_ASSOC);
        $correctPassword = password_verify($password, $userData['password'] ?? '');

        if (password_needs_rehash($userData['password'], PASSWORD_ARGON2ID)) {
            $statemet = $this->pdo->prepare('UPDATE users SET passowrd = ? WHERE id =?');
            $statemet->bindValue(1, password_hash($password, PASSWORD_ARGON2ID));
            $statemet->bindValue(2, $userData['id']);
            $statemet->execute();
        };


        if ($correctPassword) {
            $_SESSION['logado'] = true;
            header('Location: /');
        } else {
            header('Location: /login?sucesso=0');
        }
    }
}