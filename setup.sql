CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(50),
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
  role_id INT AUTO_INCREMENT PRIMARY KEY,
  role_name VARCHAR(50)
);

CREATE TABLE user_roles (
  user_role_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  role_id INT,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

CREATE TABLE games (
    game_id INT AUTO_INCREMENT PRIMARY KEY,
    game_name VARCHAR(100)
);

CREATE TABLE scores (
    score_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    game_id INT,
    score INT DEFAULT 1000,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (game_id) REFERENCES games(game_id)
);

CREATE TABLE pending_games (
    pending_game_id INT AUTO_INCREMENT PRIMARY KEY,
    requester_id INT,
    requested_user_id INT,
    game_id INT,
    result TINYINT(1) DEFAULT NULL,  # 0 for lose, 1 for win
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (requester_id) REFERENCES users(user_id),
    FOREIGN KEY (requested_user_id) REFERENCES users(user_id),
    FOREIGN KEY (game_id) REFERENCES games(game_id)
);

INSERT INTO roles (role_name) VALUES ('admin');
INSERT INTO roles (role_name) VALUES ('user');

INSERT INTO users (username, email, password)
VALUES ('admin', 'admin@wnc.ac.uk', '$5$rounds=535000$fzIMJOJ1xSGhktPa$P9YGlOHVDLRpq8Fpr92kM2zCluFeh4lyiohICV51Ly6');

INSERT INTO roles (role_name)
VALUES ('admin')
ON DUPLICATE KEY UPDATE role_id = LAST_INSERT_ID(role_id);

SET @admin_role_id = (SELECT role_id FROM roles WHERE role_name = 'admin' LIMIT 1);

INSERT INTO user_roles (user_id, role_id)
VALUES (
    (SELECT user_id FROM users WHERE username = 'admin'),
    @admin_role_id
);