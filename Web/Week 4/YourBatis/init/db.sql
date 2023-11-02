use ctf;
create table users(id int, username varchar(64), password varchar(64));
insert into users values(1, 'admin', 'admin'), (2, 'test', 'test'), (3, 'guest', 'guest');