use ctf;
create table userinfo(id int, name varchar(64), email varchar(64));
insert into userinfo values(1, 'bob', 'guest.bob@exp10it.cn'),(2, 'alice', 'user.alice@exp10it.cn'), (3, 'marry', 'admin.marry@exp10it.cn');
create table flag(flag varchar(64));
insert into flag values('0xGame{4286b62d-c37e-4010-ba9c-35d47641fb91}');