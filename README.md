
# End-to-end (E2EE) Encrypted Email Server


Table of Contents
=================

   * [Description](#description)
   * [DNS](#dns)
   * [Encryption](#encription)
      * [ENCRYPT the Mail Store](#encrypt-the-mail-store)
   * [Postfix](#postfix)
      * [SSL / Let's Encrypt](#ssl-lets-encrypt)
   * [Dovecot](#dovecot)
   * [GPGIT](#gpgit)
   * [Amavis](#amavis)
   * [Postgray](#postgray)
   * [OpenDKIM](#opendkim)
   * [Spamassassin](#spamassassin)


# Description

Secure (reasonably) host your own e-mail accounts, as e-mail was originally designed to work!

Let's make ourselves more independent from corporations, from others minding our own business, and most important, re-gain control of our personal communication over the web, in this case specifically over e-mail.

Yes, those electronic mail boxes that others maintain for us, the technical infrastructure that give us this ability to communicate instantly with everyone all over the planet, this last revision of what long ago was smoke messages, or carrier pigeons, through the centuries of postal systems, till the actual technology, where we do have, now, nor knowledge or control about every part of the entire mechanism, but hey, they give it to us for free!!!

So

Corporations and governments read and/or store all our emails, plus, we can't even complain about it anymore (from august 2013), and that doesn't mean necessary "spying" until it eventually became that.

And if you're ok with it, then you don't need this tutorial

But in case you are not, good news, i'm going to explain here how to set up an End-to-end encrypted ([E2EE](https://ssd.eff.org/en/glossary/end-end-encryption)) email server, and hosting it in your personal server at home.
I'm assuming here you know how to configure a reasonably secure server at home, but if you don't, you can check my [Raspbian Secure Server Config Tutorial](https://github.com/d3cod3/raspbian-server) first.

# DNS

So, we'll start with the DNS records, and obviously we need a domain, we can buy one through some hosting platform, or we can obtain one for free (with some limitations, on the name for example). Take a look at [FreeDNS](https://freedns.afraid.org/) if you want to learn more about free DNS hosting and domain hosting.
So we'll use here an example domain called _supersecure.mydomain.net_, and just to avoid confusion, a possible mail address could be:
_amazinguser@supersecure.mydomain.net_.
We are using here a different subdomain to avoid the disruption of the standard mail service usually packed with standard hosting services, for example _mymail@mydomain.net_, so we will maintain the standard mail service on our domain and add a new super-secure encrypted one on a subdomain.
When we have our domain, we'll just need to configure it to point to our public IP address:

- **DNS A** record, that maps your domain name to the IP address
```bash
supersecure  A   YOUR_IPv4_ADDRESS
```

- **MX** record, which tells to the others mail servers where deliver mails
```bash
supersecure           MX      supersecure.mydomain.net
```

- **TXT/SPF** record, a Sender Policy Framework (SPF) record in order to not be considered a spammer
```bash
default._domainkey.supersecure    TXT     v=DKIM1; h=sha256; p=v=DKIM1;h=sha256;k=rsa;p=YOUR_DKIM_KEY; s=email; t=s
supersecure                       txt     v=DKIM1;h=sha256;k=rsa;p=YOUR_DKIM_KEY
supersecure                       TXT     v=spf1 a mx ip4:YOUR_IPv4_ADDRESS ip6:YOUR_IPv6_ADDRESS ~all
```

- **TXT/SPF** record, DMARC record in order to not be considered a spammer by big e-mail providers (google, yahoo, etc...)
```bash
supersecure           TXT     v=DMARC1; p=none
_dmarc.supersecure    TXT     v=DMARC1; p=none
```

Regarding the **YOUR_DKIM_KEY** field, we'll work on that later, when configuring OpenDKIM (Domain Keys Identified Mail sender authentication system), so you can wait for that, or jump to the section and close the DNS records config right now, your choice!

That's a standard scenario, fell free to customize yours!

Usually DNS propagation takes a while, so it could be useful to set it at the beginning.

One easy step more, edit the file _/etc/mailname_

```bash
sudo nano /etc/mailname
```

and enter your selected mail domain name, in our case _supersecure.mydomain.net_

Let's start talking about encryption!

# ENCRYPTION

Ok, this step is delicate, so i'll start describing what we're trying to achieve here:
first i want an encrypted mail store for my mail server, but most important, i want every mail account associated with a gpg public key to asymmetrically encrypt messages, so only the users, with his/her private gpg key, will be able to decrypt and read their messages, plus, in case of server compromised, the attacker will own only a bunch of gpg encrypted texts!

So, before we start implementing this, a little reminder:

> Even if you're using the best encrypted super secure mail account of the entire universe, when you write to someone that don't, well, your conversation is potentially already compromised. A reasonably secure conversation over the web must be encrypted on both sides.

If you ended up here not randomly, probably you already know that, but just in case, check this tutorial from Free Software Foundation about [email self-defense](https://emailselfdefense.fsf.org/en/)

Perfect, let's analyze in depth how and why we'll implement the required conditions to obtain such server encryption level.

## ENCRYPT the Mail Store

I'll start with the easy one, encrypt the mail store, and for that we'll use [gocryptfs](https://nuetzlich.net/gocryptfs/), a project inspired by [EncFS](https://vgough.github.io/encfs/)

### WHY

Someone could be asking, why encrypt the mail store if we are going to asymmetrically encrypt every single message with users public gpg keys?
Well, is actually a redundancy, but let's consider this, on one side we'll learn how to properly configure generic encrypted filesystem in user-space, and on another side, we can consider it as planting some kind of honeypot for possible attackers; imagine someone taking control of our server, with read/write access to our mail store, he/she will rapidly detect the presence of gocryptfs, that, like every filesystem encryption mechanism, is potentially vulnerable to some kind of advanced attacks, so he/she will probably start to try to exploit the gocryptfs vulnerabilities (if your are interested, take a look at this audit [here](https://defuse.ca/audits/gocryptfs.htm)), and after some time, maybe, with some luck, he/she will decrypt the mail store, finding a bunch of asymmetric gpg encrypted messages!!! Wouldn't you like, just in that moment, to see his/her face?
And to go further, we could plant some other kind of hidden side-channel remote logging system over our encrypted mail store, in order to try to extract information about our potential attacker working on our compromised server, but this is just a little far away from the purposes and skill level of this tutorial, so i'll let this particular point in the hands of the interested enthusiast contributor that will teach us how to implement this properly (thanks in advance!).

### HOW

As always, let's install it:

```bash
sudo apt-get install gocryptfs
```

Then create our encrypted filesystem and the mount point, basically we'll create two folders (where you prefer):

```bash
mkdir cipher plain
```

Init our encrypted filesystem (our folder for the mailstore):

```bash
gocryptfs -init cipher
```

and mount it:

```bash
gocryptfs cipher plain
```

We can now try a little test, just listing the content of the folder where we created the two folders, _cypher_ and _plain_ (or whatever names you used)

```bash
ls -la
```

And we will obtain

```bash
ls: cannot access plain: Permission denied
```

But if we list it as sudo

```bash
sudo ls -la
```

obviously no problem!

That's all, we now have a password protected encrypted folder for our mail store. If you want to try it, just create some text file inside the plain folder, and you 'll find a new encrypted file inside cipher folder. Any time we want to mount our plain folder, we just use the second command again.

# POSTFIX

Postfix is a Mail Transfer Agent (MTA), that is, software that sends and receives emails to and from other computers on the network using the Simple Mail Transfer Protocol (SMTP). And as a reminder:

* POP/IMAP are used by a client to read messages from an email server
* SMTP is used to exchange emails between computers

So, let's install it:

```bash
sudo apt-get install postfix
```

A command line GUI will pop up, configure it as follow:

* Internet Site
* your mail server domain: _supersecure.mydomain.net_

Postfix configuration file is located at _/etc/postfix/main.cf_, in case you'll need to change more settings

Here follows a basic configuration:

```bash
myhostname = supersecure.mydomain.net
myorigin = /etc/mailname

append_dot_mydomain = no
readme_directory = no
config_directory = /etc/postfix
inet_interfaces = all
inet_protocols = ipv4
mydestination = supersecure.mydomain.net, supersecure.mydomain.net, localhost.localdomain, localhost
relayhost =
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
```
Now, the default for postfix is to use the _mbox_ format (one single file to store all messages) or the _Maildir_ format (each email stored in a individual file), but we are going to take it a step further and use Dovecot instead, so be patient, we are now going to set up our SSL/TLS certificates, and come back here for the Dovecot part in a bit.


## SSL / Let's Encrypt

We are using here the amazing free, automated and open Certificate Authority called [Let's Encrypt](https://letsencrypt.org/), a project by the [Linux Foundation](https://www.linuxfoundation.org/)

As always, install the module:

```bash
sudo apt-get install letsencrypt
```

And run the certificate creation process:

```bash
sudo letsencrypt certonly --standalone -d <supersecure.mydomain.net>
```

Replace here <supersecure.mydomain.net> with your domain name, obviusly! (and without the < > ...)

Then follow the process:

  1.  Use the default vhost filesystem
  2.  Enter your email server domain name: ex. _supersecure.mydomain.net_
  3.  Enter a contact emails
  4.  Read and agree to Let's Encrypt Terms of Service (only if you agree)
  5.  Select the _Secure_ option (HTTPS ONLY)

That's it, if everything went ok, you will have your certificates stored under _/etc/letsencrypt/live/<supersecure.mydomain.net>_

Now we need to enable SMTP-AUTH on Postfix, which will allow a client to identify itself through the authentication mechanism SASL. TLS (Transport Layer Security) will be used to encrypt the authentication process, and once authenticated, our server will allow the client to relay mail.

Here follow the config to add to _/etc/postfix/main.cf_

```bash
smtp_use_tls = yes
smtp_tls_CApath = /etc/ssl/certs
smtp_tls_cert_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
smtp_tls_key_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem
smtp_tls_security_level = may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

smtpd_use_tls=yes
smtpd_tls_CApath = /etc/ssl/certs
smtpd_tls_cert_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem

smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtpd_sasl_auth_enable = yes
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous

smtpd_tls_eecdh_grade = strong
smtpd_tls_mandatory_ciphers = medium
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_security_level = may

smtpd_banner = $myhostname ESMTP

smtpd_recipient_restrictions = permit_mynetworks, reject_invalid_hostname, reject_non_fqdn_hostname, reject_non_fqdn_sender, reject_rbl_client sbl.spamhaus.org, reject_unknown_sender_domain, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination, check_policy_service unix:private/policy-spf
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination

tls_medium_cipherlist = AES128+EECDH:AES128+EDH
tls_preempt_cipherlist = yes

policy-spf_time_limit = 3600s
```

Now, one trick more to have a even better security, generate new [_Diffie Hellman Keys_](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)

```bash
openssl gendh -out /etc/postfix/dh_512.pem -2 512
openssl gendh -out /etc/postfix/dh_2048.pem -2 2048
```

And add it to _/etc/postfix/main.cf_

```bash
smtpd_tls_dh1024_param_file = /etc/postfix/dh_2048.pem
smtpd_tls_dh512_param_file = /etc/postfix/dh_512.pem
```

Then we can edit the other Postfix important config file, _/etc/postfix/master.cf_

```bash
sudo nano /etc/postfix/master.cf
```

And make sure you have this:

```bash
smtp      inet  n       -       -       -       -       smtpd

submission       inet    n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth

smtps     inet  n       -       -       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
```

We'll come back later at this file, so study it a little bit and get comfortable with it.

Right, so we have our MTA (Mail Transfer Agent) half configured, already secured with Let's Encrypt certificates and a strong encryption settings; but why only half configured, well, for example our MTA didn't know anything, yet, about possible recipients, who are they? and how we want email to be stored?

Setting up a mail server is not an easy task, especially when we are trying to build up a reasonably secure one (and amazingly encrypted :P), so one step at the time, no rush here, the goal is to learn more as possible, because at the time we'll have this tutorial finished and our mail server up and running, it wouldn't be unusual to have to change or add something in order to avoid the possibility of some brand new attack vector.

But i'm changing course, so let's get back to work, next story, [Dovecot](https://www.dovecot.org/), the open source IMAP and POP3 email server written with security primarily in mind.

# DOVECOT

The usual first step, install it:

```bash
sudo apt-get install dovecot-core dovecot-imapd dovecot-lmtpd dovecot-pgsql postgresql postfix-pgsql
```

As you can see, i've decided to install the dovecot PostgreSQL, and that's because we will use a PostgreSQL database to securely encrypt and store the mail users (our recipients) data.

Someone could be asking right now, why PostgreSQL and not MySQL or MongoDB or whatever, and the answer is: there is not just one answer!
So to get to the point fast, let's use a line from [_The Database Hacker's Handbook_](https://www.wiley.com/en-gb/The+Database+Hacker%27s+Handbook%3A+Defending+Database+Servers-p-9780764578014), _"By default, PostgreSQL is probably the most security-aware database available ..."_.

So here we are, program and modules installed, now the tricky part, the configuration, and i think now it's time, like Agent Cooper use to say, for a damn fine cup of coffee!

We'll start with the _/etc/dovecot/dovecot.conf_ file

```bash
sudo nano /etc/dovecot/dovecot.conf
```

And set this:

```bash
# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol

listen = *

disable_plaintext_auth = yes
mail_privileged_group = mail

passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
protocols = imap lmtp

namespace inbox {
  inbox = yes

  mailbox Trash {
    auto = subscribe # autocreate and autosubscribe the Trash mailbox
    special_use = \Trash
  }
  mailbox Sent {
    auto = subscribe # autocreate and autosubscribe the Sent mailbox
    special_use = \Sent
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
      group = postfix
      mode = 0600
      user = postfix
    }
}
protocol lmtp {
    postmaster_address=postmaster@<supersecure.mydomain.net>
    hostname=<supersecure.mydomain.net>
}

ssl = required
ssl_cert = </etc/letsencrypt/live/<supersecure.mydomain.net>/fullchain.pem
ssl_cipher_list = AES128+EECDH:AES128+EDH
ssl_dh_parameters_length = 4096
ssl_key = </etc/letsencrypt/live/<supersecure.mydomain.net>/privkey.pem
ssl_prefer_server_ciphers = yes
ssl_protocols = !SSLv3

userdb {
  driver = prefetch
}

userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf
}

```

So we have connected Dovecot with Postfix, configured a standard inbox for mails, configured the SSL/TLS certificates and instructed Dovecot to search for user data in a SQL database with access specified in _/etc/dovecot/dovecot-sql.conf_ file, so let's edit that one:

```bash
sudo nano /etc/dovecot/dovecot-sql.conf
```

And we edit it as follows:

```bash
driver = pgsql
userdb_warning_disable = yes
connect = host=/var/run/postgresql/ dbname=<your_db_name> user=<your_db_user>
default_pass_scheme = SHA512
password_query = SELECT email as user, password FROM users WHERE email = '%u'
user_query = SELECT email as user, 'maildir:/your_mailstore_path/plain/maildir/'||maildir as mail, '/your_mailstore_path/plain/home/'||maildir as home, 500 as uid, 500 as gid FROM users WHERE email = '%u'
```

We'll leave _dbname_ and _user_ alone just for now, because we haven't created our database to store users data yet, so let's do it, and we'll come back here later.

The idea here is to have the less identifiable information stored in plain on our server, so we will design the simplest of user table structure in our database, with the following fields:

```bash
  Column  |           Type           |   Modifiers   
----------+--------------------------+---------------
 email    | text                     | not null
 pgpkey   | text                     | not null
 password | text                     | not null
 maildir  | text                     | not null
 created  | timestamp with time zone | default now()
```

Where _pgpkey_ field will store the public key related with the email in order to automatically encrypt every receiving message, each user with his public key. The other fields are the common ones, the complete email, the SHA512 hashed password, the timestamp of the mail creation and the name of the directory (_maildir_) in our mailstore were Dovecot will be store (and automatically encrypt thanks to more stuff we'll see later) every user message.

So, first things first, we need now to create the database, and a database user, and that is a really straightforward process, but if you're not familiar with PostgreSQL, let's have a quick recap:

0. Just before we start, let's setup the Postgres Database, first we edit _/etc/postgresql/9.4/main/pg_ident.conf_ file (my version is 9.4, so check yours before for the correct file path)
```bash
sudo nano /etc/postgresql/9.4/main/pg_ident.conf
```

and make it look like this

```bash
# MAPNAME       SYSTEM-USERNAME         PG-USERNAME

mailmap		       dovecot			          testuser
mailmap		       postfix			          testuser
mailmap		       root			              testuser
```

Where _testuser_ will be the name of the postgres user we will use for accessing the mailstore database

then edit _/etc/postgresql/9.4/main/pg_hba.conf_ file

```bash
sudo nano /etc/postgresql/9.4/main/pg_hba.conf
```

and add this line (Warning: Make sure to add it right after the **Put your actual configuration here** comment block! Otherwise one of the default entries might catch first and the database authentication will fail)

```bash
local       mail    all     peer map=mailmap
```

save it and reload postgresql service

```bash
sudo service postgresql reload
```

1.  On Debian, PostgreSQL is installed with a default user and default database both called _postgres_, so

2.  we'll connect to the PostgreSQL console with this default user and
```bash
psql -U postgres -h localhost
```

3.  create our database for the mailstore,
```bash
CREATE DATABASE mailstore_db;
```

4.  create a db user to access this new database (choose your preferred username and password) and
```bash
CREATE USER testuser WITH PASSWORD 'test_password';
```

5.  grant all the necessary privileges to this new db user.
```bash
GRANT ALL PRIVILEGES ON DATABASE "mailstore_db" to testuser;
```

6.  Now exit the PostgreSQL console
```bash
\q
```

7.  And re-log into the PostgreSQL console as the new created _testuser_, to edit our new created db _mailstore_db_
```bash
psql -U testuser -d mailstore_db -h localhost
```

8. And finally, we create our tables, the one for the users, and another one for aliases
```bash
CREATE TABLE users (
  email text NOT NULL,
  pgpkey text NOT NULL,
  password text NOT NULL,
  maildir text NOT NULL,
  created TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE aliases (
  alias text NOT NULL,
  email text NOT NULL
);
```

9.  now we check that everything is in it's right place, we list the databases
```bash
\l
```

my output:

```bash
List of databases
      Name      |   Owner    | Encoding |   Collate   |    Ctype    |   Access privileges   
----------------+------------+----------+-------------+-------------+-----------------------
 mailstore_db   | testuser   | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres       | postgres   | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
```

10. we list the _mailstore_db_ tables
```bash
\dt
```

```bash
List of relations
Schema |  Name   | Type  |   Owner    
-------+---------+-------+------------
public | aliases | table | testuser
public | users   | table | testuser
```

11. and the tables structure
```bash
\d users
```

```bash
  Column  |           Type           |   Modifiers   
----------+--------------------------+---------------
 email    | text                     | not null
 pgpkey   | text                     | not null
 password | text                     | not null
 maildir  | text                     | not null
 created  | timestamp with time zone | default now()
```

```bash
\d aliases
```

```bash
 Column | Type | Modifiers
--------+------+-----------
 alias  | text | not null
 email  | text | not null
```

12. And here we are! We have now our database ready, we can come back to the _/etc/dovecot/dovecot-sql.conf_ file, and finally configure the db name and db username:

```bash
sudo nano /etc/dovecot/dovecot-sql.conf
```

and we edit the specific line:

```bash
connect = host=/var/run/postgresql/ dbname=mailstore_db user=testuser
```

Right after that, we can now tell postfix to deliver mail directly to dovecot, so we open again _/etc/postfix/main.cf_ and added

```bash
mailbox_transport = lmtp:unix:private/dovecot-lmtp
alias_maps = hash:/etc/aliases proxy:pgsql:/etc/postfix/pgsql-aliases.cf
local_recipient_maps = proxy:pgsql:/etc/postfix/pgsql-boxes.cf $alias_maps
```

then we need to create two files, first _/etc/postfix/pgsql-aliases.cf_

```bash
user=testuser
dbname=mailstore_db
table=aliases
select_field=alias
where_field=email
hosts=unix:/var/run/postgresql
```

and then _/etc/postfix/pgsql-boxes.cf_

```bash
user=testuser
dbname=mailstore_db
table=users
select_field=email
where_field=email
hosts=unix:/var/run/postgresql/
```

This is done!

Now restart Dovecot and Postfix to apply the new settings

```bash
sudo service postfix restart
sudo service dovecot restart
```

Amazing! Now, theoretically, we are already able to send and receive emails using secure authentication , **BUT**, in order to be able to do that, we have to create our first user mail account! And how we do that? Well, we just need to add a correct entry in our _users_ table inside our postgres database.

A little digression about a possible scenario here, we could imagine some sort of form in a webpage, for everyone or maybe just for a few (your choice), to sign up and obtain an email account in our server.

Ok, So i'm _astronaut57_, i use this aka almost everywhere on the internet (is it true?, or is it just for the story? you decide!), and, while surfing the web, i happen to enter into this amazing and little mysterious webpage where i can sign up and obtain a really interesting reasonably secure gpg encrypted email account, and i start to think: why not? So the webpage seem legit, i like the Terms of Use, is free and [everything is in it's right place](https://www.youtube.com/watch?v=bD2j0fH6-UQ), let's have one, i'm thinking _astronaut57@supersecure.mydomain.net_

The form moment then, i see that is a really simple one, really straightforward, it don't ask for my telephone number, or my street address in case i loose my devices and for some reason the mail provider decide to send me, printed in paper, the last 7 GB of received emails, or for the name of my dog, among other tipical questions you have to answer when registering for a free (free?) service. No, this form is neat, it ask me for those simple things:

1.  the email name, _astronaut57@supersecure.mydomain.net_, check
2.  the pgp public key you want to associate with this mail account, i create a pgp keypair in my machine at home (or my laptop) associated with this new email, and paste here the public key, check
3.  the password for the account, _*****************************_, check

And that's it, push register button and a message appear that in, let's say, 1 minute, my new email account will be available, with a link to the mail config guide for thunderbird & enigmail. Yes, no checking your email in a browser, this kind of reasonably secure gpg encrypted email account cannot work with the actual browsers security standards. Sound pro!

That's it, the user is happy, but let's analyze the server side now, we obtain from the online form all the necessary info to add a new entry in our mailstore database _users_ table, so when the user push the register button, we check all the fields (front-end side) and if all is correct, we call a script to add a new entry in our database. I'm not going to cover here how to do that from the front-end, but i'm going to show how to do it the old fashioned way, from the terminal

First of all, we need to SHA512 the password entered by the user, yes, because we have configured dovecot to work with SHA512 password scheme, but most important because we do not want to know anything about the passwords used by our users, so we hash it:

```bash
doveadm pw -s sha512 -r 100
```

Enter the password twice and we will obtain something like this:

```bash
{SHA512}NieQminDE4Ggcewn98nKl3Jhgq7Smn3dLlQ1MyLPswq7njpt8qwsIP4jQ2MR1nhWTQyNMFkwV19g4tPQSBhNeQ==
```

Let's save that somewhere (a variable maybe?) and continue

We log into the PostgreSQL console

```bash
psql -U testuser -d mailstore_db -h localhost
```

then we add the new entry

```bash
INSERT INTO aliases ( alias,email ) VALUES (
  'astronaut57',
  'astronaut57@supersecure.mydomain.net'
);
```

and

```bash
INSERT INTO users ( email,pgpkey,password,maildir ) VALUES (
'astronaut57@supersecure.mydomain.net',
'
-----BEGIN PGP PUBLIC KEY BLOCK-----
................................................................
................................................................
-----END PGP PUBLIC KEY BLOCK-----
',
'{SHA512}NieQminDE4Ggcewn98nKl3Jhgq7Smn3dLlQ1MyLPswq7njpt8qwsIP4jQ2MR1nhWTQyNMFkwV19g4tPQSBhNeQ==',
'astronaut57/'
);
```

And exit PostgreSQL console.
```bash
\q
```

Done, user created and added to the database.

It's time to test the system, sending an email to and from _astronaut57@supersecure.mydomain.net_, and to properly do that, we'll need to configure our thunderbird client imagining we are the real _astronaut57_.

So Thunderbird, new account, with this settings:

1.  Your name:          <THE_USER_NAME_OR_WHATEVER>
2.  Email address:      astronaut57@supersecure.mydomain.net
3.  Password:           <THE_USER_PASSWORD>
4.  Incoming:           IMAP    |    supersecure.mydomain.net    |    993   |   SSL/TLS   |  Normal password
5.  Outgoing:           SMTP    |    supersecure.mydomain.net    |    587   |   STARTTLS  |  Normal password
6.  Username:           astronaut57@supersecure.mydomain.net    |    astronaut57@supersecure.mydomain.net

DONE!

If everything went ok, all the config files are correct and the DNS of your server are working, then you will be able now to send and receive emails from/to your new email address _astronaut57@supersecure.mydomain.net_

But where is the encryption? Well, we have some more work to do, so next story, [GPGIT](https://gitlab.com/mikecardwell/gpgit)!

# GPGIT


# AMAVIS


# POSTGRAY


# OPENDKIM


# SPAMASSASSIN
