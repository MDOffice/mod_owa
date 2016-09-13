REM
REM This type is needed by Java interfaces
REM

create or replace type OWA_ARRAY as table of VARCHAR2(32767);
/

REM
REM Table to hold documents as LOBs
REM

create table DEMO_DOCUMENTS
             (
             ID               number                          not null,
             PARENT_ID        number         default 0        not null,
             NAME             varchar2(250)                   not null,
             LNAME            varchar2(250)                   not null,
             NODE_TYPE        char(1)        default 'F'      not null,
             USER_ID          number         default 0        not null,
             GROUP_ID         number         default 0        not null,
             LAST_MODIFIED    date           default SYSDATE  not null,
             LINK_ID          number                                  ,
             MIME_TYPE        varchar2(80)                            ,
             FILE_PATH        varchar2(2000)                          ,
             BIN_CONTENT      blob                                    ,
             CHAR_CONTENT     clob                                    ,
             constraint DEMO_DOCUMENTS_PK primary key (ID)            ,
             constraint DEMO_DOCUMENTS_C1 check (LNAME = lower(NAME)) ,
             constraint DEMO_DOCUMENTS_C2 check (NODE_TYPE in ('D','L','F'))
             )
             LOB (BIN_CONTENT) store as DEMO_BLOB,
             LOB (CHAR_CONTENT) store as DEMO_CLOB;

create unique index DEMO_DOCUMENTS_U1
    on DEMO_DOCUMENTS (LNAME, PARENT_ID);

create unique index DEMO_DOCUMENTS_U2
    on DEMO_DOCUMENTS (PARENT_ID, ID);

create unique index DEMO_DOCUMENTS_U3
    on DEMO_DOCUMENTS (ID, PARENT_ID);

create sequence DEMO_DOCUMENTS_S
          start with 100000 maxvalue 999999 increment by 1 nocycle;

REM
REM Tables used for LONG and LONG RAW testing
REM

create table DEMO_DOC_CHARS (ID       number  not null,
                             CONTENT  long            ,
                             constraint DEMO_DOC_CHARS_PK primary key (ID));

create table DEMO_DOC_RAWS  (ID       number  not null,
                             CONTENT  long raw        ,
                             constraint DEMO_DOC_RAWS_PK primary key (ID));

REM
REM Seed data for root directory and "/docs".
REM

insert into DEMO_DOCUMENTS (ID, PARENT_ID, NAME, LNAME, NODE_TYPE)
 values (0, -1, '/', '/', 'D');

insert into DEMO_DOCUMENTS (ID, PARENT_ID, NAME, LNAME, NODE_TYPE)
 select DEMO_DOCUMENTS_S.NEXTVAL, 0, 'docs', 'docs', 'D' from dual;

insert into DEMO_DOCUMENTS (ID, PARENT_ID, NAME, LNAME, NODE_TYPE)
 select DEMO_DOCUMENTS_S.NEXTVAL, 0, 'long', 'long', 'D' from dual;

insert into DEMO_DOCUMENTS (ID, PARENT_ID, NAME, LNAME, NODE_TYPE)
 select DEMO_DOCUMENTS_S.NEXTVAL, 0, 'file', 'file', 'D' from dual;

commit;

REM
REM Table of usernames/passwords for authorization checks
REM
create table DEMO_USERS
             (
             USERNAME         varchar2(250)                   not null,
             PASSWORD         varchar2(250)                   not null,
             constraint DEMO_USERS_PK primary key (USERNAME)
             );

insert into DEMO_USERS (USERNAME, PASSWORD) values ('scott', 'tiger');

commit;

REM
REM Table to demonstrate document upload/download using WebDB method
REM
create table DEMO_DOCLOAD
             (
             NAME         varchar2(256) not null,
             MIME_TYPE    varchar2(128)         ,
             DOC_SIZE     number                ,
             DAD_CHARSET  varchar2(128)         ,
             LAST_UPDATED date                  ,
             CONTENT_TYPE varchar2(128)         ,
             BLOB_CONTENT BLOB                  ,
             constraint DEMO_DOCLOAD_PK primary key (NAME)
             );
