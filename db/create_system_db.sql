CREATE TABLE wordlist (
   lang text,
   id integer,
   word text,
   entropy integer
);

CREATE UNIQUE INDEX wordlist_pk on wordlist (lang, id);

CREATE TABLE i18n (
    lang text,
    id integer,
    phrase text
);

CREATE UNIQUE INDEX i18n_pk on i18n (lang, id);

INSERT INTO i18n VALUES ('en', 1, 'I want to have this conversation in English language');
INSERT INTO i18n VALUES ('de', 2, 'Ich möchte diese Unterhaltung auf Deutsch führen');
' add more languages here
