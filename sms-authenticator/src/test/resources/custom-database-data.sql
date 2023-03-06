create table if not exists users(
  username varchar(64) not null primary key,
  password varchar(64) not null,
  email varchar(128),
  firstName varchar(128) not null,
  lastName varchar(128) not null,
  birthDate DATE not null );

delete from users;
insert into users(username,password,email, firstName, lastName,birthDate) values('user1','changeme','jean.premier@example.com', 'Jean', 'Premier', PARSEDATETIME('1970-01-01','yyyy-MM-dd'));
insert into users(username,password,email, firstName, lastName,birthDate) values('user2','changeme','louis.second@example.com','Louis', 'Second', PARSEDATETIME('1970-01-01','yyyy-MM-dd'));
insert into users(username,password,email, firstName, lastName,birthDate) values('user3','changeme','philippe.troisieme@example.com','Philippe', 'Troisième', PARSEDATETIME('1970-01-01','yyyy-MM-dd'));

  