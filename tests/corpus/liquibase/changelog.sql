--liquibase formatted sql
--changeset alice:1
CREATE TABLE app_users (id NUMBER, name VARCHAR2(100));
--rollback DROP TABLE app_users;
INSERT INTO app_users (id, name) VALUES (1, 'Smith & Co');
