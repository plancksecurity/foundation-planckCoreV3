CREATE TABLE wordlist (
   lang text,
   id integer,
   word text,
   entropy integer
);

CREATE UNIQUE INDEX wordlist_pk on wordlist (lang, id);

CREATE TABLE i18n (
    lang text primary key,
    phrase text
);

INSERT INTO i18n VALUES ('en', 'I want to have this conversation in English language');
INSERT INTO i18n VALUES ('de', 'Ich möchte diese Unterhaltung auf Deutsch führen');
-- add more languages here
