CREATE TABLE wordlist (
   lang text,
   id integer,
   word text,
   entropy integer
);

CREATE UNIQUE INDEX wordlist_pk on wordlist (lang, id);
