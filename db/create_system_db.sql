-- DDL

CREATE TABLE i18n_language (
    lang text primary key,
    name text
);

CREATE TABLE wordlist (
    lang text
        references i18n_language (lang),
    id integer,
    word text,
    entropy integer
);

CREATE UNIQUE INDEX wordlist_pk on wordlist (lang, id);

CREATE TABLE i18n_token (
    lang text
        references i18n_language (lang),
    id integer,
    phrase text
);

CREATE UNIQUE INDEX i18n_token_pk on i18n_token (lang, id);

-- DML

INSERT INTO i18n_language VALUES ('en', 'English');
INSERT INTO i18n_token VALUES ('en', 1000, 'I want to display the trustwords in English language');

INSERT INTO i18n_language VALUES ('de', 'Deutsch');
INSERT INTO i18n_token VALUES ('de', 1000, 'Ich möchte die Trustwords auf Deutsch haben');

INSERT INTO i18n_language VALUES ('fr', 'Français');
INSERT INTO i18n_token VALUES ('fr', 1000, 'Je voudrais afficher les trustwords en Français');

INSERT INTO i18n_language VALUES ('es', 'Español');
INSERT INTO i18n_token VALUES ('es', 1000, 'Quiero mostrar las trustwords en español');

INSERT INTO i18n_language VALUES ('ca', 'Català');
INSERT INTO i18n_token VALUES ('ca', 1000, 'Vull mostrar les trustwords en català');
-- add more languages here

