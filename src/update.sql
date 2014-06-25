create table trust (
   user_id text references person (id) on delete cascade,
   pgp_keypair_fpr text references pgp_keypair (fpr) on delete cascade,
   comm_type integer not null,
   comment text
);

create unique index trust_index on trust (
   user_id,
   pgp_keypair_fpr
);

insert into trust (user_id, pgp_keypair_fpr, comm_type)
    select user_id, main_key_id, comm_type from identity;

alter table identity rename to identity_old;

create table identity (
	address text primary key,
	user_id text
		references person (id)
		on delete cascade,
	main_key_id text
		references pgp_keypair (fpr)
		on delete set null,
	comment text
);

insert into identity (address, user_id, main_key_id)
    select address, user_id, main_key_id from identity_old;

drop table identity_old;

